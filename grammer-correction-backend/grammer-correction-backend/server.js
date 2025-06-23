const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const OpenAI = require('openai');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// OpenAI Configuration
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || 'fallback-key'
});

// JWT Secret (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Simple in-memory user storage (in production, use a database)
const users = [
  {
    id: 1,
    username: 'testuser',
    password: '$2a$10$1234567890abcdef' // This will be properly hashed
  }
];

// Initialize default user with hashed password
bcrypt.hash('password123', 10).then(hash => {
  users[0].password = hash;
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Health check endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Grammar Correction API is running!',
    endpoints: {
      login: 'POST /api/login',
      grammarCheck: 'POST /api/grammar-check (requires auth)',
      health: 'GET /api/health'
    }
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Grammar check endpoint
app.post('/api/grammar-check', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;

    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }

    if (text.length > 5000) {
      return res.status(400).json({ error: 'Text too long. Maximum 5000 characters allowed.' });
    }

    // Call OpenAI API for grammar checking
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: `You are a grammar and spelling checker. Analyze the given text and return a JSON response with the following structure:
          {
            "correctedText": "The fully corrected version of the text",
            "errors": [
              {
                "original": "original word/phrase",
                "correction": "corrected word/phrase",
                "startIndex": number,
                "endIndex": number,
                "type": "grammar|spelling|punctuation",
                "message": "brief explanation of the error"
              }
            ]
          }
          
          Only return valid JSON. Do not include any other text or explanations.`
        },
        {
          role: "user",
          content: text
        }
      ],
      temperature: 0.1
    });

    let result;
    try {
      result = JSON.parse(completion.choices[0].message.content);
    } catch (parseError) {
      // Fallback if OpenAI doesn't return valid JSON
      result = {
        correctedText: text,
        errors: []
      };
    }

    res.json({
      success: true,
      originalText: text,
      ...result
    });

  } catch (error) {
    console.error('Grammar check error:', error);

    if (error.status === 401) {
      res.status(401).json({ error: 'OpenAI API authentication failed' });
    } else if (error.status === 429) {
      res.status(429).json({ error: 'Rate limit exceeded. Please try again later.' });
    } else {
      res.status(500).json({ error: 'Grammar check service temporarily unavailable' });
    }
  }
});

// Logout endpoint (client-side token removal, but good to have for logging)
app.post('/api/logout', authenticateToken, (req, res) => {
  // In a real app, you might want to blacklist the token
  res.json({ success: true, message: 'Logged out successfully' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Grammar Correction API running on port ${PORT}`);
  console.log(`📝 Test credentials: username: testuser, password: password123`);
  console.log(`🔗 API Base URL: http://localhost:${PORT}`);
});

module.exports = app;