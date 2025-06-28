require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const { v4: uuidv4 } = require('uuid');
const dayjs = require('dayjs');

const app = express();
app.use(express.json());

app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://stream11.vercel.app',
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
  return jwt.sign({
    twitch_id: data.twitch_id,
    username: data.username
  }, SECRET_KEY, { expiresIn: '14d' });
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

router.get('/auth/twitch', (req, res) => {
  const clientId = process.env.TWITCH_CLIENT_ID;
  const redirect_uri = `${process.env.BACKEND_URL}/api/auth/twitch/callback`;
  const url = `https://id.twitch.tv/oauth2/authorize?client_id=${clientId}&redirect_uri=${redirect_uri}&response_type=code&scope=user:read:email&force_verify=true`;
  res.json({ url });
});

router.get('/auth/twitch/callback', async (req, res, next) => {
  try {
    const code = req.query.code;
    if (!code) throw { status: 400, message: "Code missing" };
    // Exchange code, fetch user data (using fetch/httpx equivalent)
    // Upsert into db.users ...
    const token = createToken({ twitch_id, username });
    res.cookie('session_token', token, {
      httpOnly: true,
      secure: false,
      maxAge: 14 * 24 * 60 * 60 * 1000,
      sameSite: 'lax'
    });
    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  } catch (err) { next(err); }
});

router.post('/predictions', authMiddleware, async (req, res, next) => {
  const { game_type, title, option_a, option_b, duration_minutes = 10 } = req.body;
  const now = new Date();
  const prediction = {
    id: uuidv4(),
    twitch_id: req.user.twitch_id,
    username: req.user.username,
    game_type, title, option_a, option_b,
    status: 'active',
    created_at: now,
    ends_at: new Date(now.getTime() + duration_minutes * 60000),
    votes_a: 0, votes_b: 0, total_votes: 0, points_distributed: 0
  };
  await db.collection('predictions').insertOne(prediction);
  res.json(prediction);
});

// Add GET, vote, resolve, etc... following same approach

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

const port = process.env.PORT || 8001;
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
