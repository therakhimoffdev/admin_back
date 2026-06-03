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

// ======================== PROFESSIONAL LOGGER ========================
const LOG_LEVELS = { INFO: 'INFO', WARN: 'WARN', ERROR: 'ERROR', DEBUG: 'DEBUG' };
const isDev = process.env.NODE_ENV === 'development';

function formatLog(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = { timestamp, level, message, ...meta };
    return JSON.stringify(logEntry);
}

function logInfo(message, meta = {}) {
    console.log(formatLog(LOG_LEVELS.INFO, message, meta));
}

function logWarn(message, meta = {}) {
    console.warn(formatLog(LOG_LEVELS.WARN, message, meta));
}

function logError(message, meta = {}) {
    console.error(formatLog(LOG_LEVELS.ERROR, message, meta));
}

function logDebug(message, meta = {}) {
    if (isDev) console.debug(formatLog(LOG_LEVELS.DEBUG, message, meta));
}

// Request ID generator (simple sequential with process uptime)
let requestCounter = 0;
function generateRequestId() {
    return `req-${Date.now()}-${(++requestCounter) % 10000}`;
}

// Request logging middleware
app.use((req, res, next) => {
    req.requestId = generateRequestId();
    req.startTime = Date.now();
    logInfo(`Incoming request`, {
        requestId: req.requestId,
        method: req.method,
        path: req.path,
        ip: getClientIp(req),
        userAgent: req.headers['user-agent']?.substring(0, 100),
    });
    // Capture response finish
    const originalJson = res.json;
    const originalSend = res.send;
    res.json = function (data) {
        res._body = data;
        return originalJson.call(this, data);
    };
    res.send = function (body) {
        res._body = body;
        return originalSend.call(this, body);
    };
    res.on('finish', () => {
        const duration = Date.now() - req.startTime;
        const level = res.statusCode >= 500 ? LOG_LEVELS.ERROR : (res.statusCode >= 400 ? LOG_LEVELS.WARN : LOG_LEVELS.INFO);
        const logFunc = res.statusCode >= 500 ? logError : (res.statusCode >= 400 ? logWarn : logInfo);
        logFunc(`Request completed`, {
            requestId: req.requestId,
            method: req.method,
            path: req.path,
            statusCode: res.statusCode,
            durationMs: duration,
            contentLength: res.get('Content-Length') || '?',
        });
    });
    next();
});

// ─── Vercel uchun muhim: trust proxy ──────────────────────────────
app.set('trust proxy', true);

// ─── Middleware ────────────────────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '50kb' }));

const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:5173', 'http://localhost:5174'];

app.use(cors({
    origin: (origin, cb) => {
        if (!origin || allowedOrigins.some(o => origin.startsWith(o.trim()))) {
            cb(null, true);
        } else {
            cb(null, true);
        }
    },
    credentials: true,
}));

// Rate limit
const trackLimit = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { error: 'Too many requests' },
    skip: (req) => process.env.NODE_ENV === 'development',
});

const adminLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
});

// ─── MongoDB ───────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
    .then(() => logInfo('MongoDB connected', { uri: process.env.MONGODB_URI?.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@') }))
    .catch(err => logError('MongoDB connection error', { error: err.message }));

// ─── Helpers ─────────────────────────────────────────────────────────
function getClientIp(req) {
    return (
        req.headers['cf-connecting-ip'] ||
        req.headers['x-real-ip'] ||
        (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
        req.socket.remoteAddress ||
        '0.0.0.0'
    ).replace('::ffff:', '');
}

async function getIpInfo(ip) {
    const geo = geoip.lookup(ip);
    const base = {
        country: geo?.country || 'Unknown',
        countryCode: geo?.country || 'XX',
        region: geo?.region || 'Unknown',
        city: geo?.city || 'Unknown',
        lat: geo?.ll?.[0] || 0,
        lon: geo?.ll?.[1] || 0,
        timezone: geo?.timezone || 'Unknown',
        isp: 'Unknown',
        org: 'Unknown',
    };

    if (process.env.IPINFO_TOKEN && ip !== '127.0.0.1' && ip !== '::1') {
        try {
            const res = await fetch(`https://ipinfo.io/${ip}/json?token=${process.env.IPINFO_TOKEN}`, {
                signal: AbortSignal.timeout(2000),
            });
            if (res.ok) {
                const d = await res.json();
                const [lat, lon] = (d.loc || '0,0').split(',').map(Number);
                return {
                    country: d.country_name || d.country || base.country,
                    countryCode: d.country || base.countryCode,
                    region: d.region || base.region,
                    city: d.city || base.city,
                    lat, lon,
                    timezone: d.timezone || base.timezone,
                    isp: d.hostname || base.isp,
                    org: d.org || base.org,
                };
            }
        } catch (err) {
            logWarn('IP info fetch failed', { ip, error: err.message });
        }
    }
    return base;
}

function detectVpnFromOrg(org = '') {
    const vpnKeywords = [
        'vpn', 'proxy', 'tor', 'nordvpn', 'expressvpn', 'surfshark', 'mullvad',
        'protonvpn', 'hidemyass', 'cyberghost', 'ipvanish', 'privateinternetaccess',
        'pia', 'windscribe', 'tunnelbear', 'm247', 'datacamp', 'quadranet',
        'choopa', 'vultr', 'linode', 'digitalocean', 'hetzner', 'ovh', 'leaseweb',
    ];
    const lc = org.toLowerCase();
    return vpnKeywords.some(k => lc.includes(k));
}

function parseUserAgent(ua) {
    const parser = new UAParser(ua);
    const result = parser.getResult();
    return {
        userAgent: ua,
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

// ─── TRACK ENDPOINT (with logging) ───────────────────────────────────
app.post('/api/track', trackLimit, async (req, res) => {
    const requestId = req.requestId;
    logDebug('Track endpoint called', { requestId });
    try {
        const ip = getClientIp(req);
        const ua = req.headers['user-agent'] || '';
        const body = req.body || {};

        logDebug('Collecting visitor data', { requestId, ip, uaLength: ua.length });

        const [geoData, deviceData] = await Promise.all([
            getIpInfo(ip),
            Promise.resolve(parseUserAgent(ua)),
        ]);

        const isVpn = detectVpnFromOrg(geoData.org);
        const isReturning = await Visitor.exists({
            ip,
            visitedAt: { $lt: new Date(), $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        });

        const visitor = new Visitor({
            ip,
            vpnDetected: isVpn || body.webrtcLeak?.detected || false,
            vpnDetails: {
                isVpn,
                isProxy: false,
                isTor: false,
                isHosting: /hosting|datacenter|cloud/i.test(geoData.org),
                org: geoData.org,
                asn: '',
            },
            geo: geoData,
            device: deviceData,
            client: {
                screenWidth: body.screen?.width,
                screenHeight: body.screen?.height,
                viewportWidth: body.viewport?.width,
                viewportHeight: body.viewport?.height,
                colorDepth: body.screen?.colorDepth,
                pixelRatio: body.screen?.pixelRatio,
                language: body.language,
                languages: body.languages || [],
                timezone: body.timezone,
                cookiesEnabled: body.cookies,
                touchSupport: body.touch?.supported,
                maxTouchPoints: body.touch?.maxPoints,
                onLine: body.onLine,
                platform: body.platform,
                doNotTrack: body.doNotTrack,
                hardwareConcurrency: body.hardware?.cpuCores,
                deviceMemory: body.hardware?.memory,
            },
            page: {
                url: body.page?.url,
                title: body.page?.title,
                referrer: body.page?.referrer,
                path: body.page?.path,
            },
            webrtcLeak: body.webrtcLeak || { detected: false, localIps: [] },
            fingerprint: body.fingerprint || {},
            sessionId: body.sessionId,
            pageLoadTime: body.loadTime,
            country: geoData.countryCode,
            isReturning: !!isReturning,
        });

        await visitor.save();
        logInfo('Visitor saved successfully', { requestId, visitorId: visitor._id, ip, country: geoData.countryCode });
        res.status(200).json({ ok: true });
    } catch (err) {
        logError('Track endpoint error', { requestId, error: err.message, stack: err.stack });
        res.status(500).json({ error: 'Tracking failed' });
    }
});

// ─── ADMIN AUTH MIDDLEWARE (with logging) ──────────────────────────
async function adminAuth(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token;
    const maskedToken = token ? token.substring(0, 8) + '...' : 'missing';
    if (!token) {
        logWarn('Admin auth failed: token missing', { requestId: req.requestId, path: req.path });
        return res.status(401).json({ error: 'Token required' });
    }
    try {
        const admin = await Admin.findOne({ token, isActive: true });
        if (!admin) {
            logWarn('Admin auth failed: invalid token', { requestId: req.requestId, path: req.path, tokenPrefix: maskedToken });
            return res.status(401).json({ error: 'Invalid or inactive token' });
        }
        admin.lastUsed = new Date();
        await admin.save();
        req.admin = admin;
        logInfo('Admin authenticated', { requestId: req.requestId, adminId: admin._id, username: admin.username, role: admin.role });
        next();
    } catch (err) {
        logError('Admin auth database error', { requestId: req.requestId, error: err.message });
        res.status(500).json({ error: 'Database error' });
    }
}

// ─── ADMIN ENDPOINTS (with logging) ─────────────────────────────────

// Dashboard stats
app.get('/api/admin/stats', adminLimit, adminAuth, async (req, res) => {
    const requestId = req.requestId;
    try {
        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const thisWeek = new Date(now - 7 * 24 * 60 * 60 * 1000);
        const thisMonth = new Date(now.getFullYear(), now.getMonth(), 1);

        const [
            totalVisitors,
            todayVisitors,
            weekVisitors,
            monthVisitors,
            vpnCount,
            mobileCount,
            botCount,
            returningCount,
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

        logInfo('Stats fetched', { requestId, totalVisitors, todayVisitors });
        res.json({
            totalVisitors,
            todayVisitors,
            weekVisitors,
            monthVisitors,
            vpnCount,
            mobileCount,
            botCount,
            returningCount,
            vpnPercent: totalVisitors ? Math.round((vpnCount / totalVisitors) * 100) : 0,
            mobilePercent: totalVisitors ? Math.round((mobileCount / totalVisitors) * 100) : 0,
        });
    } catch (err) {
        logError('Stats endpoint error', { requestId, error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// Visitors list
app.get('/api/admin/visitors', adminLimit, adminAuth, async (req, res) => {
    const requestId = req.requestId;
    try {
        const {
            page = 1,
            limit = 20,
            search = '',
            country = '',
            vpn = '',
            device = '',
            sortBy = 'visitedAt',
            sortOrder = 'desc',
            dateFrom,
            dateTo,
        } = req.query;

        const filter = {};
        if (search) {
            filter.$or = [
                { ip: { $regex: search, $options: 'i' } },
                { 'geo.city': { $regex: search, $options: 'i' } },
                { 'geo.country': { $regex: search, $options: 'i' } },
                { 'device.browser': { $regex: search, $options: 'i' } },
                { 'page.url': { $regex: search, $options: 'i' } },
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

        const sort = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };
        const skip = (parseInt(page) - 1) * parseInt(limit);

        const [visitors, total] = await Promise.all([
            Visitor.find(filter).sort(sort).skip(skip).limit(parseInt(limit)).lean(),
            Visitor.countDocuments(filter),
        ]);

        logInfo('Visitors list fetched', { requestId, total, page, limit });
        res.json({ visitors, total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)), limit: parseInt(limit) });
    } catch (err) {
        logError('Visitors list error', { requestId, error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// Single visitor
app.get('/api/admin/visitors/:id', adminLimit, adminAuth, async (req, res) => {
    const requestId = req.requestId;
    const visitorId = req.params.id;
    try {
        const visitor = await Visitor.findById(visitorId).lean();
        if (!visitor) {
            logWarn('Visitor not found', { requestId, visitorId });
            return res.status(404).json({ error: 'Not found' });
        }
        logInfo('Visitor details fetched', { requestId, visitorId });
        res.json(visitor);
    } catch (err) {
        logError('Visitor details error', { requestId, visitorId, error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// Daily chart
app.get('/api/admin/charts/daily', adminLimit, adminAuth, async (req, res) => {
    const requestId = req.requestId;
    try {
        const days = parseInt(req.query.days) || 30;
        const from = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
        const data = await Visitor.aggregate([
            { $match: { visitedAt: { $gte: from } } },
            {
                $group: {
                    _id: {
                        year: { $year: '$visitedAt' },
                        month: { $month: '$visitedAt' },
                        day: { $dayOfMonth: '$visitedAt' },
                    },
                    count: { $sum: 1 },
                    vpn: { $sum: { $cond: ['$vpnDetected', 1, 0] } },
                    mobile: { $sum: { $cond: ['$device.isMobile', 1, 0] } },
                },
            },
            { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } },
        ]);
        logInfo('Daily chart fetched', { requestId, days, points: data.length });
        res.json(data.map(d => ({
            date: `${d._id.year}-${String(d._id.month).padStart(2, '0')}-${String(d._id.day).padStart(2, '0')}`,
            count: d.count,
            vpn: d.vpn,
            mobile: d.mobile,
        })));
    } catch (err) {
        logError('Daily chart error', { requestId, error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// Countries chart
app.get('/api/admin/charts/countries', adminLimit, adminAuth, async (req, res) => {
    const requestId = req.requestId;
    try {
        const data = await Visitor.aggregate([
            { $group: { _id: '$geo.country', code: { $first: '$geo.countryCode' }, count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 15 },
        ]);
        logInfo('Countries chart fetched', { requestId, countries: data.length });
        res.json(data.map(d => ({ country: d._id || 'Unknown', code: d.code, count: d.count })));
    } catch (err) {
        logError('Countries chart error', { requestId, error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// Browsers chart
app.get('/api/admin/charts/browsers', adminLimit, adminAuth, async (req, res) => {
    const requestId = req.requestId;
    try {
        const data = await Visitor.aggregate([
            { $group: { _id: '$device.browser', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 },
        ]);
        logInfo('Browsers chart fetched', { requestId });
        res.json(data.map(d => ({ browser: d._id || 'Unknown', count: d.count })));
    } catch (err) {
        logError('Browsers chart error', { requestId, error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// OS chart
app.get('/api/admin/charts/os', adminLimit, adminAuth, async (req, res) => {
    const requestId = req.requestId;
    try {
        const data = await Visitor.aggregate([
            { $group: { _id: '$device.os', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 },
        ]);
        logInfo('OS chart fetched', { requestId });
        res.json(data.map(d => ({ os: d._id || 'Unknown', count: d.count })));
    } catch (err) {
        logError('OS chart error', { requestId, error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// Device types chart
app.get('/api/admin/charts/devices', adminLimit, adminAuth, async (req, res) => {
    const requestId = req.requestId;
    try {
        const data = await Visitor.aggregate([
            {
                $group: {
                    _id: { $ifNull: ['$device.deviceType', 'desktop'] },
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } },
        ]);
        logInfo('Device types chart fetched', { requestId });
        res.json(data.map(d => ({ device: d._id, count: d.count })));
    } catch (err) {
        logError('Device types chart error', { requestId, error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// Delete single visitor
app.delete('/api/admin/visitors/:id', adminLimit, adminAuth, async (req, res) => {
    const requestId = req.requestId;
    const visitorId = req.params.id;
    try {
        const result = await Visitor.findByIdAndDelete(visitorId);
        if (!result) {
            logWarn('Delete failed: visitor not found', { requestId, visitorId });
            return res.status(404).json({ error: 'Visitor not found' });
        }
        logInfo('Visitor deleted', { requestId, visitorId });
        res.json({ ok: true });
    } catch (err) {
        logError('Delete visitor error', { requestId, visitorId, error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// Clear all visitors
app.delete('/api/admin/visitors', adminLimit, adminAuth, async (req, res) => {
    const requestId = req.requestId;
    try {
        if (req.query.confirm !== 'yes') {
            logWarn('Clear all visitors missing confirmation', { requestId });
            return res.status(400).json({ error: 'Add ?confirm=yes' });
        }
        const result = await Visitor.deleteMany({});
        logInfo('All visitors cleared', { requestId, deletedCount: result.deletedCount });
        res.json({ ok: true, deletedCount: result.deletedCount });
    } catch (err) {
        logError('Clear all visitors error', { requestId, error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    logDebug('Health check', { requestId: req.requestId });
    res.json({ status: 'ok', time: new Date() });
});

// ─── Vercel uchun eksport ─────────────────────────────────────────
export default app;