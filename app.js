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

  res.status(200).json({message: 'Login successful', accessToken, refreshToken });
});

// Protected route
app.get('/api/user', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'No token' });

  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, ACCESS_SECRET);
    res.json({ email: decoded.email });
  } catch (err) {
    res.status(403).json({ message: 'Invalid or expired token' });
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
