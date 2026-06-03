import mongoose from 'mongoose';

const visitorSchema = new mongoose.Schema({
    // Network
    ip: { type: String, index: true },
    realIp: String,
    vpnDetected: { type: Boolean, default: false },
    vpnDetails: {
        isVpn: Boolean,
        isProxy: Boolean,
        isTor: Boolean,
        isHosting: Boolean,
        org: String,
        asn: String,
    },

    // Geo
    geo: {
        country: String,
        countryCode: String,
        region: String,
        city: String,
        lat: Number,
        lon: Number,
        timezone: String,
        isp: String,
        org: String,
    },

    // Device
    device: {
        userAgent: String,
        browser: String,
        browserVersion: String,
        os: String,
        osVersion: String,
        deviceType: String, // mobile, tablet, desktop
        deviceVendor: String,
        deviceModel: String,
        isMobile: Boolean,
        isBot: Boolean,
    },

    // Screen & Client
    client: {
        screenWidth: Number,
        screenHeight: Number,
        viewportWidth: Number,
        viewportHeight: Number,
        colorDepth: Number,
        pixelRatio: Number,
        language: String,
        languages: [String],
        timezone: String,
        cookiesEnabled: Boolean,
        touchSupport: Boolean,
        maxTouchPoints: Number,
        onLine: Boolean,
        platform: String,
        doNotTrack: String,
        hardwareConcurrency: Number,
        deviceMemory: Number,
    },

    // Page info
    page: {
        url: String,
        title: String,
        referrer: String,
        path: String,
    },

    // WebRTC leak detection
    webrtcLeak: {
        detected: Boolean,
        localIps: [String],
    },

    // Fingerprint signals
    fingerprint: {
        fonts: [String],
        canvas: String,
        webgl: String,
        audioContext: Boolean,
        plugins: Number,
        adBlock: Boolean,
    },

    // Meta
    sessionId: { type: String, index: true },
    visitedAt: { type: Date, default: Date.now, index: true },
    updatedAt: { type: Date, default: Date.now },
    pageLoadTime: Number, // ms
    country: String, // denormalized for quick queries
    isReturning: { type: Boolean, default: false },
}, {
    timestamps: true,
});

visitorSchema.index({ visitedAt: -1 });
visitorSchema.index({ 'geo.country': 1 });
visitorSchema.index({ ip: 1, visitedAt: -1 });

export default mongoose.model('Visitor', visitorSchema);