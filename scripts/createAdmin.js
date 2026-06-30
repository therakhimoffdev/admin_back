import mongoose from 'mongoose';
import dotenv from 'dotenv';
import Admin from '../models/Admin.js';

dotenv.config();

async function createAdmin() {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://therakhimoffdev_db_user:40g948_SA@cluster0.31ebssu.mongodb.net/');
    const token = Admin.generateToken();
    const admin = new Admin({
        username: 'therakhimoff',
        email: 'therakhimoff.dev@gmail.com',
        token: token,
        role: 'superadmin'
    });
    await admin.save();
    console.log('✅ Admin yaratildi. Quyidagi tokenni frontend login sahifasiga kiriting:');
    console.log(token);
    process.exit(0);
}

createAdmin();