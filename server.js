import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { UAParser } from 'ua-parser-js';
import geoip from 'geoip-lite';
import dotenv from 'dotenv';
import Visitor from './models/Visitors.js';
import Admin from './models/Admin.js';

dotenv.config();

const app = express();
const isDev = process.env.NODE_ENV !== 'production';

// ======================== LOGGER ========================
function formatLog(level, message, meta = {}) {
    return JSON.stringify({
        timestamp: new Date().toISOString(),
        level,
        message,
        env: process.env.NODE_ENV || 'unknown',
        ...meta,
    });
}
const logger = {
    info: (msg, meta = {}) => console.log(formatLog('INFO', msg, meta)),
    warn: (msg, meta = {}) => console.warn(formatLog('WARN', msg, meta)),
    error: (msg, meta = {}) => console.error(formatLog('ERROR', msg, meta)),
    debug: (msg, meta = {}) => { if (isDev) console.debug(formatLog('DEBUG', msg, meta)); },
};

// ======================== MONGODB ========================
let mongoConnected = false;

async function connectMongo() {
    if (mongoConnected && mongoose.connection.readyState === 1) return;

    const uri = process.env.MONGODB_URI;
    if (!uri) throw new Error('MONGODB_URI is not configured');

    await mongoose.connect(uri, {
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 10000,
        maxPoolSize: 10,
    });
    mongoConnected = true;
    logger.info('MongoDB connected', { uri: uri.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@') });
}

mongoose.connection.on('disconnected', () => { mongoConnected = false; logger.warn('MongoDB disconnected'); });
mongoose.connection.on('error', (err) => { mongoConnected = false; logger.error('MongoDB error', { error: err.message }); });

// ======================== HELPERS ========================
function getClientIp(req) {
    const env = process.env.DEPLOYMENT_ENV || 'production';
    const forwarded = req.headers['x-forwarded-for'];

    if (forwarded) {
        const ips = forwarded.split(',').map(ip => ip.trim().replace('::ffff:', ''));
        if (env === 'ngrok' || env === 'local') {
            const first = ips[0];
            if (first && first !== '127.0.0.1' && first !== '::1') return first;
        } else {
            for (let i = ips.length - 1; i >= 0; i--) {
                if (isPublicIp(ips[i])) return ips[i];
            }
            return ips[0];
        }
    }
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp) return cfIp.trim();
    const realIp = req.headers['x-real-ip'];
    if (realIp) return realIp.trim();
    return (req.socket?.remoteAddress || '0.0.0.0').replace('::ffff:', '');
}

function isPublicIp(ip) {
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') return false;
    if (/^10\./.test(ip)) return false;
    if (/^192\.168\./.test(ip)) return false;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return false;
    if (/^169\.254\./.test(ip)) return false;
    return true;
}

async function getIpInfo(ip) {
    const geo = geoip.lookup(ip);
    const base = {
        country: geo?.country || 'Unknown',
        countryCode: geo?.country || 'XX',
        region: geo?.region || 'Unknown',
        city: geo?.city || 'Unknown',
        lat: geo?.ll?.[0] ?? 0,
        lon: geo?.ll?.[1] ?? 0,
        timezone: geo?.timezone || 'Unknown',
        isp: 'Unknown',
        org: 'Unknown',
        asn: '',
        operator: '',
        connectionType: 'unknown',
    };

    const token = process.env.IPINFO_TOKEN;
    if (token && isPublicIp(ip)) {
        try {
            const res = await fetch(`https://ipinfo.io/${ip}/json?token=${token}`, {
                signal: AbortSignal.timeout(3000),
            });
            if (res.ok) {
                const d = await res.json();
                const [lat, lon] = (d.loc || '0,0').split(',').map(Number);
                const { asn, companyName } = parseOrgField(d.org || '');
                const operator = detectOperator(d.org || '', asn);
                const connectionType = detectConnectionType(operator, d.org || '');

                return {
                    country: d.country_name || d.country || base.country,
                    countryCode: d.country || base.countryCode,
                    region: d.region || base.region,
                    city: d.city || base.city,
                    lat: isNaN(lat) ? base.lat : lat,
                    lon: isNaN(lon) ? base.lon : lon,
                    timezone: d.timezone || base.timezone,
                    isp: companyName || d.hostname || base.isp,
                    org: d.org || base.org,
                    asn,
                    operator,
                    connectionType,
                };
            }
        } catch (err) {
            logger.warn('IPInfo fetch failed', { ip, error: err.message });
        }
    }
    return base;
}

// ======================== O'ZBEKISTON OPERATORLARINI ANIQLASH ========================
const OPERATOR_PATTERNS = [
    { name: 'Beeline', asn: ['AS28910'], keywords: ['unitel', 'beeline'] },
    { name: 'Ucell', asn: ['AS41202'], keywords: ['coscom', 'ucell'] },
    { name: 'Mobiuz', asn: ['AS29426'], keywords: ['universal mobile systems', 'ums', 'mobiuz'] },
    { name: 'UzMobile', asn: ['AS8193', 'AS201767'], keywords: ['uztelecom', 'uzbektelecom', 'uzmobile'] },
    { name: 'Perfectum', asn: [], keywords: ['perfectum'] },
    { name: 'Humans', asn: [], keywords: ['humans'] },
];

function detectOperator(org = '', asn = '') {
    const orgLc = org.toLowerCase();
    const asnUp = (asn || '').toUpperCase();

    for (const op of OPERATOR_PATTERNS) {
        if (op.asn.includes(asnUp)) return op.name;
        if (op.keywords.some(k => orgLc.includes(k))) return op.name;
    }
    return '';
}

function parseOrgField(org = '') {
    const match = /^(AS\d+)\s+(.*)$/.exec(org.trim());
    if (match) return { asn: match[1], companyName: match[2] };
    return { asn: '', companyName: org };
}

function detectConnectionType(operatorName, org = '') {
    if (operatorName) return 'mobile';
    const orgLc = org.toLowerCase();
    if (/hosting|datacenter|cloud|vps/.test(orgLc)) return 'hosting';
    if (/telecom|fiber|broadband|isp/.test(orgLc)) return 'broadband';
    return 'unknown';
}

// ======================== VPN ANIQLASH ========================
const VPN_KEYWORDS = [
    'vpn', 'proxy', 'tor', 'nordvpn', 'expressvpn', 'surfshark', 'mullvad',
    'protonvpn', 'hidemyass', 'cyberghost', 'ipvanish', 'privateinternetaccess',
    'pia', 'windscribe', 'tunnelbear', 'm247', 'datacamp', 'quadranet',
    'choopa', 'vultr', 'linode', 'digitalocean', 'hetzner', 'ovh', 'leaseweb',
];

function detectVpnFromOrg(org = '') {
    const lc = org.toLowerCase();
    return VPN_KEYWORDS.some(k => lc.includes(k));
}

function parseUserAgent(ua) {
    if (!ua) return {
        userAgent: '', browser: 'Unknown', browserVersion: '',
        os: 'Unknown', osVersion: '', deviceType: 'desktop',
        deviceVendor: '', deviceModel: '', isMobile: false, isBot: false,
    };
    const parser = new UAParser(ua);
    const result = parser.getResult();
    return {
        userAgent: ua.substring(0, 500),
        browser: result.browser.name || 'Unknown',
        browserVersion: result.browser.version || '',
        os: result.os.name || 'Unknown',
        osVersion: result.os.version || '',
        deviceType: result.device.type || 'desktop',
        deviceVendor: result.device.vendor || '',
        deviceModel: result.device.model || '',
        isMobile: result.device.type === 'mobile' || result.device.type === 'tablet',
        isBot: /bot|crawler|spider|crawl|slurp|curl|wget/i.test(ua),
    };
}

// ======================== REQUEST LOGGING ========================
let requestCounter = 0;
app.use((req, res, next) => {
    req.requestId = `req-${Date.now()}-${(++requestCounter) % 100000}`;
    req.startTime = Date.now();
    logger.info('Incoming request', {
        requestId: req.requestId,
        method: req.method,
        path: req.path,
        ip: getClientIp(req),
        origin: req.headers['origin'],
    });
    res.on('finish', () => {
        const duration = Date.now() - req.startTime;
        const fn = res.statusCode >= 500 ? logger.error : res.statusCode >= 400 ? logger.warn : logger.info;
        fn('Request completed', { requestId: req.requestId, method: req.method, path: req.path, statusCode: res.statusCode, durationMs: duration });
    });
    next();
});

app.set('trust proxy', false);

// ======================== SECURITY ========================
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' }, contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// ======================== CORS ========================
const rawOrigins = process.env.ALLOWED_ORIGINS || '';
const allowedOrigins = rawOrigins
    ? rawOrigins.split(',').map(o => o.trim()).filter(Boolean)
    : ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:5174'];

app.use(cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, true);
        const allowed = allowedOrigins.some(o => origin === o || origin.startsWith(o));
        if (!allowed) logger.warn('CORS blocked', { origin });
        cb(null, true); // ehtiyot bo'ling: hozir hammaga ruxsat
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-admin-token', 'Authorization'],
}));

// ======================== RATE LIMITING ========================
const trackLimit = rateLimit({
    windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many requests. Please try again later.' },
    skip: () => isDev,
    validate: { trustProxy: false, xForwardedForHeader: false },
    keyGenerator: (req) => getClientIp(req),
});
const adminLimit = rateLimit({
    windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many admin requests.' },
    validate: { trustProxy: false, xForwardedForHeader: false },
    keyGenerator: (req) => getClientIp(req),
});

// ======================== DB MIDDLEWARE ========================
app.use(async (req, res, next) => {
    if (req.path === '/api/health') return next();
    try {
        await connectMongo();
        next();
    } catch (err) {
        logger.error('DB middleware: connection failed', { requestId: req.requestId, error: err.message });
        res.status(503).json({ error: 'Database unavailable. Please try again.' });
    }
});

// ======================== TRACK ENDPOINT (IP TARIXI BILAN) ========================
app.options('/api/track', cors()); // preflight uchun
app.get('/api/track', trackLimit, (req, res) => {
    res.status(200).json({ ok: true, message: 'Use POST for tracking data' });
});

app.post('/api/track', trackLimit, async (req, res, next) => {
    const { requestId } = req;
    try {
        const ip = getClientIp(req);
        const ua = req.headers['user-agent'] || '';
        const body = req.body || {};

        logger.debug('Track: processing', { requestId, ip });

        const [geoData, deviceData] = await Promise.all([
            getIpInfo(ip),
            Promise.resolve(parseUserAgent(ua)),
        ]);

        const isVpn = detectVpnFromOrg(geoData.org);

        const screen = body.screen || {};
        const viewport = body.viewport || {};
        const touch = body.touch || {};
        const hardware = body.hardware || {};
        const fingerprint = body.fingerprint || {};
        const webrtcLeak = body.webrtcLeak || {};

        const fingerprintId = fingerprint.id || '';
        const sessionId = body.sessionId || '';

        const dedupeKey = fingerprintId
            ? { 'fingerprint.id': fingerprintId }
            : { sessionId, ip };

        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const existingVisitor = await Visitor.findOne({
            ...dedupeKey,
            visitedAt: { $gte: thirtyDaysAgo },
        }).lean();

        const isReturning = !!existingVisitor;

        // Yangi visitor uchun to'liq ma'lumot
        const visitorData = {
            ip,
            vpnDetected: isVpn || webrtcLeak.detected || false,
            vpnDetails: {
                isVpn,
                isProxy: false,
                isTor: (geoData.org || '').toLowerCase().includes('tor'),
                isHosting: /hosting|datacenter|cloud/i.test(geoData.org),
                org: geoData.org,
                asn: geoData.asn || '',
            },
            geo: geoData,
            device: deviceData,
            client: {
                screenWidth: Number(screen.width) || 0,
                screenHeight: Number(screen.height) || 0,
                viewportWidth: Number(viewport.width) || 0,
                viewportHeight: Number(viewport.height) || 0,
                colorDepth: Number(screen.colorDepth) || 0,
                pixelRatio: Number(screen.pixelRatio) || 1,
                language: body.language || '',
                languages: Array.isArray(body.languages) ? body.languages : [],
                timezone: body.timezone || '',
                cookiesEnabled: !!body.cookies,
                touchSupport: touch.supported ?? false,
                maxTouchPoints: Number(touch.maxPoints) || 0,
                onLine: body.onLine !== undefined ? !!body.onLine : true,
                platform: body.platform || '',
                doNotTrack: body.doNotTrack,
                hardwareConcurrency: Number(hardware.cpuCores) || 0,
                deviceMemory: Number(hardware.memory) || 0,
            },
            page: {
                url: (body.page?.url || '').slice(0, 500),
                title: (body.page?.title || '').slice(0, 200),
                referrer: (body.page?.referrer || '').slice(0, 500),
                path: (body.page?.path || ''),
            },
            webrtcLeak: {
                detected: !!webrtcLeak.detected,
                localIps: Array.isArray(webrtcLeak.localIps) ? webrtcLeak.localIps : [],
                publicIps: Array.isArray(webrtcLeak.publicIps) ? webrtcLeak.publicIps : [],
            },
            fingerprint: {
                id: fingerprintId,
                canvas: fingerprint.canvas || '',
                audio: fingerprint.audio || '',
                webgl: fingerprint.webgl || '',
                webglVendor: fingerprint.webglVendor || '',
                fonts: fingerprint.fonts || '',
                hash: fingerprintId,
            },
            sessionId,
            pageLoadTime: Number(body.loadTime) || 0,
            country: geoData.countryCode,
            isReturning,
            publicIpHint: (body.publicIpHint || '').slice(0, 45),
            battery: body.battery || null,
            connection: body.connection || null,
            visitedAt: new Date(),
            lastSeenAt: new Date(),
        };

        let visitor;
        if (existingVisitor) {
            // IP tarixini boshqarish
            const existingIpEntry = (existingVisitor.ipHistory || []).find(
                entry => entry.ip === ip
            );

            if (existingIpEntry) {
                // mavjud IP uchun seenCount oshirish
                await Visitor.updateOne(
                    { _id: existingVisitor._id, 'ipHistory.ip': ip },
                    {
                        $set: {
                            'ipHistory.$.lastSeenAt': new Date(),
                            lastSeenAt: new Date(),
                            'page.url': visitorData.page.url,
                            'page.title': visitorData.page.title,
                            'page.path': visitorData.page.path,
                            onLine: visitorData.client.onLine,
                        },
                        $inc: {
                            'ipHistory.$.seenCount': 1,
                            pageviews: 1,
                        },
                    }
                );
                visitor = await Visitor.findById(existingVisitor._id);
            } else {
                // yangi IP qo'shish
                const newIpHistoryEntry = {
                    ip,
                    firstSeenAt: new Date(),
                    lastSeenAt: new Date(),
                    seenCount: 1,
                    country: geoData.country,
                    countryCode: geoData.countryCode,
                    region: geoData.region,
                    city: geoData.city,
                    lat: geoData.lat,
                    lon: geoData.lon,
                    isp: geoData.isp,
                    asn: geoData.asn,
                    operator: geoData.operator,
                    connectionType: geoData.connectionType,
                    isVpn: isVpn || false,
                };

                visitor = await Visitor.findByIdAndUpdate(
                    existingVisitor._id,
                    {
                        $set: {
                            lastSeenAt: new Date(),
                            'page.url': visitorData.page.url,
                            'page.title': visitorData.page.title,
                            'page.path': visitorData.page.path,
                            onLine: visitorData.client.onLine,
                        },
                        $push: { ipHistory: newIpHistoryEntry },
                        $inc: { pageviews: 1 },
                    },
                    { new: true }
                );
            }
        } else {
            // Yangi visitor yaratish
            visitor = new Visitor({
                ...visitorData,
                pageviews: 1,
                ipHistory: [{
                    ip,
                    firstSeenAt: new Date(),
                    lastSeenAt: new Date(),
                    seenCount: 1,
                    country: geoData.country,
                    countryCode: geoData.countryCode,
                    region: geoData.region,
                    city: geoData.city,
                    lat: geoData.lat,
                    lon: geoData.lon,
                    isp: geoData.isp,
                    asn: geoData.asn,
                    operator: geoData.operator,
                    connectionType: geoData.connectionType,
                    isVpn: isVpn || false,
                }],
            });
            await visitor.save();
        }

        logger.info('Visitor tracked', {
            requestId,
            visitorId: visitor._id.toString(),
            ip: ip.replace(/\.\d+$/, '.***'),
            country: geoData.countryCode,
            city: geoData.city,
            isVpn,
            isReturning,
            browser: deviceData.browser,
            os: deviceData.os,
            action: existingVisitor ? 'updated' : 'created',
        });

        res.status(200).json({ ok: true });
    } catch (err) {
        logger.error('Track endpoint error', { requestId, error: err.message, stack: isDev ? err.stack : undefined });
        next(err);
    }
});

// ======================== DEBUG ========================
app.get('/api/debug-ip', (req, res) => {
    res.json({
        detectedIp: getClientIp(req),
        forwarded: req.headers['x-forwarded-for'],
        realIp: req.headers['x-real-ip'],
        socket: req.socket?.remoteAddress,
        deploymentEnv: process.env.DEPLOYMENT_ENV,
    });
});

// ======================== ADMIN AUTH ========================
async function adminAuth(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token;
    if (!token || typeof token !== 'string') {
        logger.warn('Admin auth: token missing', { requestId: req.requestId, path: req.path });
        return res.status(401).json({ error: 'Token required' });
    }
    try {
        const admin = await Admin.findOne({ token, isActive: true }).lean();
        if (!admin) {
            logger.warn('Admin auth: invalid token', { requestId: req.requestId, path: req.path });
            return res.status(401).json({ error: 'Invalid or inactive token' });
        }
        Admin.updateOne({ _id: admin._id }, { lastUsed: new Date() }).catch(() => { });
        req.admin = admin;
        next();
    } catch (err) {
        next(err);
    }
}

// ======================== ADMIN ENDPOINTS ========================
app.get('/api/admin/stats', adminLimit, adminAuth, async (req, res, next) => {
    try {
        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const thisWeek = new Date(now - 7 * 24 * 60 * 60 * 1000);
        const thisMonth = new Date(now.getFullYear(), now.getMonth(), 1);

        const [
            totalVisitors, todayVisitors, weekVisitors, monthVisitors,
            vpnCount, mobileCount, botCount, returningCount,
        ] = await Promise.all([
            Visitor.countDocuments(),
            Visitor.countDocuments({ visitedAt: { $gte: today } }),
            Visitor.countDocuments({ visitedAt: { $gte: thisWeek } }),
            Visitor.countDocuments({ visitedAt: { $gte: thisMonth } }),
            Visitor.countDocuments({ vpnDetected: true }),
            Visitor.countDocuments({ 'device.isMobile': true }),
            Visitor.countDocuments({ 'device.isBot': true }),
            Visitor.countDocuments({ isReturning: true }),
        ]);

        res.json({
            totalVisitors, todayVisitors, weekVisitors, monthVisitors,
            vpnCount, mobileCount, botCount, returningCount,
            vpnPercent: totalVisitors ? Math.round((vpnCount / totalVisitors) * 100) : 0,
            mobilePercent: totalVisitors ? Math.round((mobileCount / totalVisitors) * 100) : 0,
        });
    } catch (err) {
        next(err);
    }
});

app.get('/api/admin/visitors', adminLimit, adminAuth, async (req, res, next) => {
    try {
        const {
            page = 1, limit = 20,
            search = '', country = '', vpn = '', device = '',
            sortBy = 'visitedAt', sortOrder = 'desc',
            dateFrom, dateTo,
        } = req.query;

        const parsedPage = Math.max(1, parseInt(page) || 1);
        const parsedLimit = Math.min(100, Math.max(1, parseInt(limit) || 20));

        const filter = {};
        if (search) {
            filter.$or = [
                { ip: { $regex: search, $options: 'i' } },
                { 'geo.city': { $regex: search, $options: 'i' } },
                { 'geo.country': { $regex: search, $options: 'i' } },
                { 'device.browser': { $regex: search, $options: 'i' } },
                { 'page.url': { $regex: search, $options: 'i' } },
                { 'fingerprint.id': { $regex: search, $options: 'i' } },
            ];
        }
        if (country) filter['geo.countryCode'] = country;
        if (vpn === 'true') filter.vpnDetected = true;
        if (vpn === 'false') filter.vpnDetected = false;
        if (device) filter['device.deviceType'] = device;
        if (dateFrom || dateTo) {
            filter.visitedAt = {};
            if (dateFrom) filter.visitedAt.$gte = new Date(dateFrom);
            if (dateTo) filter.visitedAt.$lte = new Date(dateTo);
        }

        const allowedSortFields = ['visitedAt', 'lastSeenAt', 'ip', 'geo.country', 'device.browser', 'device.os', 'pageviews'];
        const safeSortBy = allowedSortFields.includes(sortBy) ? sortBy : 'visitedAt';
        const sort = { [safeSortBy]: sortOrder === 'asc' ? 1 : -1 };
        const skip = (parsedPage - 1) * parsedLimit;

        const [visitors, total] = await Promise.all([
            Visitor.find(filter).sort(sort).skip(skip).limit(parsedLimit).lean(),
            Visitor.countDocuments(filter),
        ]);

        res.json({
            visitors, total,
            page: parsedPage,
            pages: Math.ceil(total / parsedLimit),
            limit: parsedLimit,
        });
    } catch (err) {
        next(err);
    }
});

app.get('/api/admin/visitors/:id', adminLimit, adminAuth, async (req, res, next) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid visitor ID' });
        const visitor = await Visitor.findById(id).lean();
        if (!visitor) return res.status(404).json({ error: 'Visitor not found' });
        res.json(visitor);
    } catch (err) { next(err); }
});

app.get('/api/admin/charts/daily', adminLimit, adminAuth, async (req, res, next) => {
    try {
        const days = Math.min(365, Math.max(1, parseInt(req.query.days) || 30));
        const from = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
        const data = await Visitor.aggregate([
            { $match: { visitedAt: { $gte: from } } },
            { $group: { _id: { year: { $year: '$visitedAt' }, month: { $month: '$visitedAt' }, day: { $dayOfMonth: '$visitedAt' } }, count: { $sum: 1 }, vpn: { $sum: { $cond: ['$vpnDetected', 1, 0] } }, mobile: { $sum: { $cond: ['$device.isMobile', 1, 0] } } } },
            { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } },
        ]);
        res.json(data.map(d => ({
            date: `${d._id.year}-${String(d._id.month).padStart(2, '0')}-${String(d._id.day).padStart(2, '0')}`,
            count: d.count, vpn: d.vpn, mobile: d.mobile,
        })));
    } catch (err) { next(err); }
});

app.get('/api/admin/charts/countries', adminLimit, adminAuth, async (req, res, next) => {
    try {
        const data = await Visitor.aggregate([
            { $group: { _id: '$geo.country', code: { $first: '$geo.countryCode' }, count: { $sum: 1 } } },
            { $sort: { count: -1 } }, { $limit: 15 },
        ]);
        res.json(data.map(d => ({ country: d._id || 'Unknown', code: d.code, count: d.count })));
    } catch (err) { next(err); }
});

app.get('/api/admin/charts/browsers', adminLimit, adminAuth, async (req, res, next) => {
    try {
        const data = await Visitor.aggregate([
            { $group: { _id: '$device.browser', count: { $sum: 1 } } },
            { $sort: { count: -1 } }, { $limit: 10 },
        ]);
        res.json(data.map(d => ({ browser: d._id || 'Unknown', count: d.count })));
    } catch (err) { next(err); }
});

app.get('/api/admin/charts/os', adminLimit, adminAuth, async (req, res, next) => {
    try {
        const data = await Visitor.aggregate([
            { $group: { _id: '$device.os', count: { $sum: 1 } } },
            { $sort: { count: -1 } }, { $limit: 10 },
        ]);
        res.json(data.map(d => ({ os: d._id || 'Unknown', count: d.count })));
    } catch (err) { next(err); }
});

app.get('/api/admin/charts/devices', adminLimit, adminAuth, async (req, res, next) => {
    try {
        const data = await Visitor.aggregate([
            { $group: { _id: { $ifNull: ['$device.deviceType', 'desktop'] }, count: { $sum: 1 } } },
            { $sort: { count: -1 } },
        ]);
        res.json(data.map(d => ({ device: d._id, count: d.count })));
    } catch (err) { next(err); }
});

app.delete('/api/admin/visitors/:id', adminLimit, adminAuth, async (req, res, next) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid visitor ID' });
        const result = await Visitor.findByIdAndDelete(id);
        if (!result) return res.status(404).json({ error: 'Visitor not found' });
        logger.info('Visitor deleted', { requestId: req.requestId, visitorId: id });
        res.json({ ok: true });
    } catch (err) { next(err); }
});

app.delete('/api/admin/visitors', adminLimit, adminAuth, async (req, res, next) => {
    try {
        if (req.query.confirm !== 'yes') return res.status(400).json({ error: 'Add ?confirm=yes to proceed' });
        const result = await Visitor.deleteMany({});
        logger.warn('All visitors cleared', { requestId: req.requestId, deletedCount: result.deletedCount });
        res.json({ ok: true, deletedCount: result.deletedCount });
    } catch (err) { next(err); }
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString(), mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected', env: process.env.NODE_ENV || 'unknown', uptime: process.uptime() });
});

app.use((req, res) => {
    logger.warn('Route not found', { requestId: req.requestId, method: req.method, path: req.path });
    res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    const statusCode = err.status || err.statusCode || 500;
    logger.error('Unhandled error', { requestId: req.requestId, statusCode, error: err.message });
    if (err.name === 'ValidationError') return res.status(400).json({ error: 'Validation failed', details: Object.values(err.errors).map(e => e.message) });
    if (err.name === 'CastError') return res.status(400).json({ error: 'Invalid ID format' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON in request body' });
    res.status(statusCode).json({ error: statusCode >= 500 ? 'Internal server error' : err.message, ...(isDev && { details: err.message }) });
});

process.on('unhandledRejection', (reason) => { logger.error('Unhandled Rejection', { reason: String(reason) }); });
process.on('uncaughtException', (err) => { logger.error('Uncaught Exception', { error: err.message }); process.exit(1); });

export default app;