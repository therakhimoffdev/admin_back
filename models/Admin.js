import mongoose from 'mongoose';
import crypto from 'crypto';

const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    token: { type: String, required: true, unique: true },
    role: { type: String, enum: ['admin', 'superadmin'], default: 'admin' },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    lastUsed: Date
});

adminSchema.statics.generateToken = function () {
    return crypto.randomBytes(32).toString('hex');
};

export default mongoose.model('Admin', adminSchema);