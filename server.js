require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { MongoClient } = require('mongodb');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch'); // add this to fetch from Twitch

const app = express();
app.use(express.json());
app.use(cookieParser());

const cors = require('cors');

app.use(cors({
  origin: 'https://stream11.vercel.app',
  credentials: true
}));

const SECRET_KEY = process.env.SECRET_KEY || require('crypto').randomBytes(32).toString('hex');

let db;

// 🔌 Connect to MongoDB
(async function connectDB() {
  const client = new MongoClient(process.env.MONGO_URL, { useUnifiedTopology: true });
  await client.connect();
  db = client.db(process.env.DB_NAME);
  console.log("✅ MongoDB connected");

  process.on('SIGINT', () => {
    client.close();
    console.log("🛑 MongoDB disconnected");
    process.exit();
  });
})();

function createToken(data) {
  return jwt.sign({ twitch_id: data.twitch_id, username: data.username }, SECRET_KEY, { expiresIn: '14d' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, SECRET_KEY);
  } catch (err) {
    const error = new Error(err.name === 'TokenExpiredError' ? 'Session expired' : 'Invalid session');
    error.status = 401;
    throw error;
  }
}

async function authMiddleware(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) return res.status(401).json({ detail: "No session token" });
  try {
    const payload = verifyToken(token);
    const user = await db.collection('users').findOne({ twitch_id: payload.twitch_id });
    if (!user) return res.status(404).json({ detail: "User not found" });
    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

const router = express.Router();

// ✅ OPTIONS handler for preflight requests
router.options('*', (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", process.env.FRONTEND_URL);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.sendStatus(200);
});

// ✅ Twitch Login URL
router.get('/auth/twitch', (req, res) => {
  const clientId = process.env.TWITCH_CLIENT_ID;
  const redirect_uri = `${process.env.BACKEND_URL}/api/auth/twitch/callback`;
  const url = `https://id.twitch.tv/oauth2/authorize?client_id=${clientId}&redirect_uri=${redirect_uri}&response_type=code&scope=user:read:email&force_verify=true`;
  res.json({ url });
});

// ✅ Twitch Callback
router.get('/auth/twitch/callback', async (req, res, next) => {
  try {
    const code = req.query.code;
    if (!code) throw { status: 400, message: "Code missing" };

    const redirect_uri = `${process.env.BACKEND_URL}/api/auth/twitch/callback`;
    const tokenResponse = await fetch('https://id.twitch.tv/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.TWITCH_CLIENT_ID,
        client_secret: process.env.TWITCH_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri
      })
    });

    const tokenData = await tokenResponse.json();
    const access_token = tokenData.access_token;

    const userResponse = await fetch('https://api.twitch.tv/helix/users', {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Client-Id': process.env.TWITCH_CLIENT_ID
      }
    });

    const userData = (await userResponse.json()).data[0];
    const twitch_id = userData.id;
    const username = userData.login;

    const userRecord = {
      twitch_id,
      username,
      display_name: userData.display_name,
      email: userData.email,
      profile_image_url: userData.profile_image_url,
      access_token,
      total_points: 1000,
      created_at: new Date(),
      last_login: new Date()
    };

    await db.collection('users').updateOne(
      { twitch_id },
      { $set: userRecord },
      { upsert: true }
    );

    const session_token = createToken({ twitch_id, username });
    res.cookie('session_token', session_token, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 14 * 24 * 60 * 60 * 1000
    });

    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  } catch (err) {
    next(err);
  }
});

router.get('/auth/status', (req, res) => {
  try {
    const token = req.cookies?.session_token;
    if (!token) return res.json({ authenticated: false });
    verifyToken(token);
    res.json({ authenticated: true });
  } catch (err) {
    res.json({ authenticated: false });
  }
});

// ✅ Health check routes
router.post('/status', async (req, res) => {
  const item = {
    id: uuidv4(),
    client_name: req.body.client_name,
    timestamp: new Date()
  };
  await db.collection('status_checks').insertOne(item);
  res.json(item);
});

router.get('/status', async (req, res) => {
  const arr = await db.collection('status_checks').find().toArray();
  res.json(arr);
});

app.use('/api', router);

// 🔥 Global error handler
app.use((err, req, res, next) => {
  console.error("❌ Error:", err);
  res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
});

// ✅ Start server (for local dev; Vercel uses serverless export)
if (require.main === module) {
  const port = process.env.PORT || 8001;
  app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));
}

module.exports = app;
