const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const connectDB = require('./config/database');
const logger = require('./utils/logger');

// Import Routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const cropRoutes = require('./routes/crop');
const uploadRoutes = require('./routes/upload');
const mlRoutes = require('./routes/ml');
const analyticsRoutes = require('./routes/analytics');

// Initialize Express App
const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
connectDB();

// Rate Limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://your-flutter-app-domain.com'] 
    : ['http://localhost:3000', 'http://10.0.2.2:3000'], // Android emulator
  credentials: true
}));
app.use(morgan('combined'));
app.use(limiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static file serving for uploads
app.use('/uploads', express.static('uploads'));

// Health Check Route
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'PMFBY Backend Server is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/crops', cropRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/ml', mlRoutes);
app.use('/api/analytics', analyticsRoutes);

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    message: `Cannot ${req.method} ${req.originalUrl}`
  });
});

// Global Error Handler
app.use((error, req, res, next) => {
  logger.error('Global error:', error);
  
  const status = error.statusCode || 500;
  const message = error.message || 'Internal Server Error';
  
  res.status(status).json({
    error: message,
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
  });
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`PMFBY Backend Server started on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV}`);
  logger.info(`Health check: http://localhost:${PORT}/health`);
});

module.exports = app;