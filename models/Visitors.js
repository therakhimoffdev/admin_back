import mongoose from 'mongoose';

const visitorSchema = new mongoose.Schema({
    // ── Network ───────────────────────────────────────────────────────────────
    ip: { type: String, index: true },
    realIp: { type: String },
    publicIpHint: { type: String }, // ipify.org orqali tasdiqlangan IP

    vpnDetected: { type: Boolean, default: false },
    vpnDetails: {
        isVpn: { type: Boolean, default: false },
        isProxy: { type: Boolean, default: false },
        isTor: { type: Boolean, default: false },
        isHosting: { type: Boolean, default: false },
        org: { type: String, default: '' },
        asn: { type: String, default: '' },
    },

    // ── Geo ───────────────────────────────────────────────────────────────────
    geo: {
        country: { type: String, default: 'Unknown' },
        countryCode: { type: String, default: 'XX' },
        region: { type: String, default: 'Unknown' },
        city: { type: String, default: 'Unknown' },
        lat: { type: Number, default: 0 },
        lon: { type: Number, default: 0 },
        timezone: { type: String, default: 'Unknown' },
        isp: { type: String, default: 'Unknown' },
        org: { type: String, default: 'Unknown' },
    },

    // ── Device (UA Parser) ────────────────────────────────────────────────────
    device: {
        userAgent: { type: String, default: '' },
        browser: { type: String, default: 'Unknown' },
        browserVersion: { type: String, default: '' },
        os: { type: String, default: 'Unknown' },
        osVersion: { type: String, default: '' },
        deviceType: { type: String, default: 'desktop' }, // mobile | tablet | desktop
        deviceVendor: { type: String, default: '' },
        deviceModel: { type: String, default: '' },
        isMobile: { type: Boolean, default: false },
        isBot: { type: Boolean, default: false },
    },

    // ── Screen & Client ───────────────────────────────────────────────────────
    client: {
        screenWidth: { type: Number },
        screenHeight: { type: Number },
        viewportWidth: { type: Number },
        viewportHeight: { type: Number },
        colorDepth: { type: Number },
        pixelRatio: { type: Number },
        language: { type: String },
        languages: [String],
        timezone: { type: String },
        cookiesEnabled: { type: Boolean },
        touchSupport: { type: Boolean },
        maxTouchPoints: { type: Number },
        onLine: { type: Boolean },
        platform: { type: String },
        doNotTrack: { type: String },
        hardwareConcurrency: { type: Number },
        deviceMemory: { type: Number },
    },

    // ── Page info ─────────────────────────────────────────────────────────────
    page: {
        url: { type: String },
        title: { type: String },
        referrer: { type: String },
        path: { type: String },
    },

    // ── WebRTC leak ───────────────────────────────────────────────────────────
    webrtcLeak: {
        detected: { type: Boolean, default: false },
        localIps: [String],
        publicIps: [String], // yangi: VPN leak aniqlash uchun
    },

    // ── Fingerprint ───────────────────────────────────────────────────────────
    fingerprint: {
        // ASOSIY: duplicate oldini olish uchun ishlatiladi
        // cookie "fpid" da saqlanadi, 30 kun bardoshli
        id: { type: String },       // ← dedupe key

        canvas: { type: String },
        audio: { type: String },       // ← AudioContext hash
        webgl: { type: String },
        webglVendor: { type: String },       // ← GPU vendor
        audioContext: { type: Boolean },
        plugins: { type: Number },
        adBlock: { type: Boolean },
        fonts: { type: String },       // join(',') — array emas, hajm kichik
    },

    // ── Network quality ───────────────────────────────────────────────────────
    connection: {
        effectiveType: { type: String },     // '4g' | '3g' | '2g' | 'slow-2g'
        downlink: { type: Number },     // Mbps
        rtt: { type: Number },     // ms
        saveData: { type: Boolean },
    },

    // ── Battery ───────────────────────────────────────────────────────────────
    battery: {
        charging: { type: Boolean },
        level: { type: Number },   // 0–100 %
        chargingTime: { type: Number },   // seconds
        dischargingTime: { type: Number },   // seconds
    },

    // ── Meta ──────────────────────────────────────────────────────────────────
    sessionId: { type: String, index: true },
    pageLoadTime: { type: Number },          // ms

    // Tez so'rovlar uchun denormalize
    country: { type: String },
    isReturning: { type: Boolean, default: false },

    // ── Duplicate prevention ──────────────────────────────────────────────────
    pageviews: { type: Number, default: 1 },
    lastSeenAt: { type: Date, default: Date.now },
    visitedAt: { type: Date, default: Date.now },
});

// ── Indekslar ─────────────────────────────────────────────────────────────────

// fingerprintId — asosiy dedupe key (sparse: bo'sh bo'lsa indekslamaydi)
visitorSchema.index({ 'fingerprint.id': 1 }, { sparse: true });

// fingerprintId yo'q hollarda fallback
visitorSchema.index({ sessionId: 1, ip: 1 });

// Admin panel uchun
visitorSchema.index({ visitedAt: -1 });
visitorSchema.index({ 'geo.countryCode': 1, visitedAt: -1 });
visitorSchema.index({ 'device.browser': 1 });
visitorSchema.index({ 'device.deviceType': 1 });
visitorSchema.index({ vpnDetected: 1, visitedAt: -1 });
visitorSchema.index({ ip: 1, visitedAt: -1 });

// Vercel serverless hot-reload uchun model cache
export default mongoose.models.Visitor || mongoose.model('Visitor', visitorSchema);