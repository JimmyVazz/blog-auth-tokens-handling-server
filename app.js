const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const cors = require('cors');
require('dotenv').config();

const app = express();

const users = []; // In-memory

const PORT = process.env.PORT || 8000;
const ACCESS_SECRET = process.env.ACCESS_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

app.use(express.json());
app.use(cookieParser());

app.use(cors({
  origin: 'http://localhost:5173', // Your frontend URL
  credentials: true,              // Allow sending cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Allowed HTTP methods
  allowedHeaders: ['Content-Type', 'Authorization'],    // Allow these headers
}));

// Helper to generate tokens
function generateTokens(user) {
  const accessToken = jwt.sign({ email: user.email }, ACCESS_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ email: user.email }, REFRESH_SECRET, { expiresIn: '7d' });
  return { accessToken, refreshToken };
}

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  const existing = users.find(u => u.email === email);
  if (existing) return res.status(400).json({ message: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  users.push({ email, password: hashed });
  res.status(201).json({ message: 'User registered' });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: 'Invalid credentials' });

  const { accessToken, refreshToken } = generateTokens(user);

  // Send refresh token as HttpOnly cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: false, // true in production with HTTPS
    sameSite: 'Lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  res.json({ accessToken });
});

app.get('/api/user', (req, res) => {
  const token = req.cookies.accessToken; // Using the cookie

  if (!token) return res.status(401).json({ message: 'No token' });

  try {
    const decoded = jwt.verify(token, ACCESS_SECRET);
    res.json({ email: decoded.email });
  } catch (err) {
    res.status(403).json({ message: 'Invalid or expired token' });
  }
});


// Refresh token
app.post('/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: 'No refresh token' });

  try {
    const decoded = jwt.verify(token, REFRESH_SECRET);
    const user = users.find(u => u.email === decoded.email);
    if (!user) return res.status(401).json({ message: 'User not found' });

    const { accessToken, refreshToken } = generateTokens(user);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ accessToken });
  } catch (err) {
    res.status(403).json({ message: 'Invalid refresh token' });
  }
});

// Logout
app.post('/logout', (req, res) => {
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out' });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
