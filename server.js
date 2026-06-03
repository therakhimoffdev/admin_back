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
// Faqat .env dan o‘qiladi, hardcoded yo‘q
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.error('❌ MongoDB error:', err));

// ─── Helpers (hech qanday o‘zgarish yo‘q) ─────────────────────────
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
        } catch (_) { }
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

// ─── TRACK ENDPOINT (Vercel’da async/ketma-ket) ───────────────────
app.post('/api/track', trackLimit, async (req, res) => {
    try {
        const ip = getClientIp(req);
        const ua = req.headers['user-agent'] || '';
        const body = req.body || {};

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
        res.status(200).json({ ok: true });
    } catch (err) {
        console.error('Track save error:', err.message);
        // Vercel’da xatolik bo‘lsa ham clientga 200 qaytarmaymiz, 500 beramiz
        res.status(500).json({ error: 'Tracking failed' });
    }
});

// ─── ADMIN AUTH MIDDLEWARE ─────────────────────────────────────────
async function adminAuth(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token;
    if (!token) {
        return res.status(401).json({ error: 'Token required' });
    }
    try {
        const admin = await Admin.findOne({ token, isActive: true });
        if (!admin) {
            return res.status(401).json({ error: 'Invalid or inactive token' });
        }
        admin.lastUsed = new Date();
        await admin.save();
        req.admin = admin;
        next();
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
}

// ─── ADMIN ENDPOINTS (o‘zgarishsiz) ────────────────────────────────
app.get('/api/admin/stats', adminLimit, adminAuth, async (req, res) => {
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
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/visitors', adminLimit, adminAuth, async (req, res) => {
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

        res.json({
            visitors,
            total,
            page: parseInt(page),
            pages: Math.ceil(total / parseInt(limit)),
            limit: parseInt(limit),
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/visitors/:id', adminLimit, adminAuth, async (req, res) => {
    try {
        const visitor = await Visitor.findById(req.params.id).lean();
        if (!visitor) return res.status(404).json({ error: 'Not found' });
        res.json(visitor);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/charts/daily', adminLimit, adminAuth, async (req, res) => {
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

        res.json(data.map(d => ({
            date: `${d._id.year}-${String(d._id.month).padStart(2, '0')}-${String(d._id.day).padStart(2, '0')}`,
            count: d.count,
            vpn: d.vpn,
            mobile: d.mobile,
        })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/charts/countries', adminLimit, adminAuth, async (req, res) => {
    try {
        const data = await Visitor.aggregate([
            { $group: { _id: '$geo.country', code: { $first: '$geo.countryCode' }, count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 15 },
        ]);
        res.json(data.map(d => ({ country: d._id || 'Unknown', code: d.code, count: d.count })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/charts/browsers', adminLimit, adminAuth, async (req, res) => {
    try {
        const data = await Visitor.aggregate([
            { $group: { _id: '$device.browser', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 },
        ]);
        res.json(data.map(d => ({ browser: d._id || 'Unknown', count: d.count })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/charts/os', adminLimit, adminAuth, async (req, res) => {
    try {
        const data = await Visitor.aggregate([
            { $group: { _id: '$device.os', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 },
        ]);
        res.json(data.map(d => ({ os: d._id || 'Unknown', count: d.count })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/charts/devices', adminLimit, adminAuth, async (req, res) => {
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
        res.json(data.map(d => ({ device: d._id, count: d.count })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/visitors/:id', adminLimit, adminAuth, async (req, res) => {
    try {
        await Visitor.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/visitors', adminLimit, adminAuth, async (req, res) => {
    try {
        if (req.query.confirm !== 'yes') return res.status(400).json({ error: 'Add ?confirm=yes' });
        await Visitor.deleteMany({});
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

// ─── Vercel uchun eksport (app.listen qo‘yilmaydi) ─────────────────
export default app;