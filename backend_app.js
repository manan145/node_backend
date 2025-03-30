import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import { Sequelize, DataTypes } from 'sequelize';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import axios from 'axios';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL Database Connection
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
  host: process.env.DB_HOST,
  dialect: 'postgres',
  logging: false,
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false, // allow self-signed certificate
    },
  },
});

// Sequelize Models
const User = sequelize.define(
  'User',
  {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, unique: true, allowNull: false },
    password_hash: { type: DataTypes.STRING, allowNull: false },
  },
  {
    tableName: 'user',
    timestamps: false,
  }
);

const Analysis = sequelize.define(
  'Analysis',
  {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    text: { type: DataTypes.TEXT, allowNull: false },
    sentiment: { type: DataTypes.STRING, allowNull: false },
    confidence: { type: DataTypes.FLOAT, allowNull: false },
    timestamp: { type: DataTypes.DATE, defaultValue: Sequelize.NOW },
    user_id: { type: DataTypes.INTEGER, allowNull: false },
  },
  {
    tableName: 'analysis',
    timestamps: false,
  }
);

User.hasMany(Analysis, { foreignKey: 'user_id' });
Analysis.belongsTo(User, { foreignKey: 'user_id' });

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Sentiment Analyzer (Hugging Face API)
const analyzeSentiment = async (text) => {
  try {
    const response = await axios.post(
      'https://api-inference.huggingface.co/models/distilbert-base-uncased-finetuned-sst-2-english',
      { inputs: text },
      {
        headers: {
          Authorization: `Bearer ${process.env.HUGGINGFACE_API_KEY}`,
        },
      }
    );
    return response.data;
  } catch (error) {
    console.error('Hugging Face API Error:', error.response?.data || error.message);
    throw new Error('Sentiment analysis failed');
  }
};

// Routes
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const existingUser = await User.findOne({ where: { email } });
  if (existingUser) {
    return res.status(400).json({ error: 'User already exists' });
  }
  const password_hash = await bcrypt.hash(password, 10);
  await User.create({ name, email, password_hash });
  res.status(201).json({ message: 'User registered successfully' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Missing email or password' });
  }
  const user = await User.findOne({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET_KEY, { expiresIn: '1d' });
  res.json({ token });
});

app.post('/analyze', authenticateToken, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'No text provided' });

  try {
    const result = await analyzeSentiment(text);
    const label = result[0].label;
    const score = result[0].score;

    await Analysis.create({
      text,
      sentiment: label,
      confidence: score,
      user_id: req.user.id,
    });

    res.json({ text, sentiment: label, confidence: score });
  } catch (err) {
    res.status(500).json({ error: 'Sentiment analysis failed' });
  }
});

app.get('/history', authenticateToken, async (req, res) => {
  const analyses = await Analysis.findAll({
    where: { user_id: req.user.id },
    order: [['timestamp', 'DESC']],
  });

  const results = analyses.map((a) => {
    const dateObj = new Date(a.timestamp);
    const formattedDate =
      dateObj.getFullYear() +
      '-' +
      String(dateObj.getMonth() + 1).padStart(2, '0') +
      '-' +
      String(dateObj.getDate()).padStart(2, '0') +
      ' ' +
      String(dateObj.getHours()).padStart(2, '0') +
      ':' +
      String(dateObj.getMinutes()).padStart(2, '0') +
      ':' +
      String(dateObj.getSeconds()).padStart(2, '0');

    return {
      id: a.id,
      text: a.text,
      sentiment: a.sentiment,
      confidence: a.confidence,
      timestamp: formattedDate,
    };
  });

  res.json(results);
});

// Start Server
sequelize.sync().then(() => {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
