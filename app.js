import express from 'express';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
process.loadEnvFile();

const app = express();
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    secret: String,
    twoFAEnabled: { type: Boolean, default: false },
});

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

const User = mongoose.model('User', userSchema);

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send('User already exists');
        }

        const user = new User({ username, password });
        await user.save();
        res.send('User registered successfully');
    } catch (error) {
        console.error('Error registering user', error);
        res.status(500).send('Internal server error');
    }
});

app.post('/setup-2fa', async (req, res) => {
    const { username } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).send('User not found');
        }

        const secret = speakeasy.generateSecret({ name: 'Blacklist' });
        user.secret = secret.base32;
        user.twoFAEnabled = false;
        await user.save();

        const qrCodeDataUrl = await qrcode.toDataURL(secret.otpauth_url);
        res.json({ qrCodeDataUrl });
    } catch (error) {
        console.error('Error setting up 2FA', error);
        res.status(500).send('Internal server error');
    }
});

app.post('/verify-2fa', async (req, res) => {
    const { username, token } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user || !user.secret) {
            return res.status(404).send('User not found or 2FA not set up');
        }

        const verified = speakeasy.totp.verify({
            secret: user.secret,
            encoding: 'base32',
            token: token,
        });

        if (verified) {
            user.twoFAEnabled = true;
            await user.save();
            res.send('2FA verified successfully');
        } else {
            res.status(401).send('Invalid token');
        }
    } catch (error) {
        console.error('Error verifying 2FA', error);
        res.status(500).send('Internal server error');
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});