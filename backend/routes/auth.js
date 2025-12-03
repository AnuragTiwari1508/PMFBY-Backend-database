const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const LoginSession = require('../models/LoginSession');
const Analytics = require('../models/Analytics');
const { verifyToken, optionalAuth } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Validation rules
const registerValidation = [
  body('fullName')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Full name must be between 2 and 100 characters'),
    
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
    
  body('phone')
    .matches(/^[6-9]\d{9}$/)
    .withMessage('Please provide a valid 10-digit Indian mobile number'),
    
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number')
];

const loginValidation = [
  body('emailOrPhone')
    .notEmpty()
    .withMessage('Email or phone number is required'),
    
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// Helper function to generate tokens and create session
const createUserSession = async (user, deviceInfo, locationInfo) => {
  try {
    // Create new login session
    const sessionData = {
      userId: user._id,
      deviceInfo: {
        deviceId: deviceInfo.deviceId || crypto.randomBytes(16).toString('hex'),
        deviceType: deviceInfo.deviceType || 'Unknown',
        deviceModel: deviceInfo.deviceModel,
        osVersion: deviceInfo.osVersion,
        appVersion: deviceInfo.appVersion,
        userAgent: deviceInfo.userAgent
      },
      loginLocation: {
        ipAddress: locationInfo.ipAddress,
        country: locationInfo.country,
        state: locationInfo.state,
        city: locationInfo.city,
        coordinates: locationInfo.coordinates
      },
      fcmToken: deviceInfo.fcmToken
    };
    
    const session = new LoginSession(sessionData);
    
    // Generate tokens
    const tokens = session.generateTokens();
    
    // Save session
    await session.save();
    
    // Update user login tracking
    await user.updateLoginTracking(deviceInfo);
    
    return {
      session,
      tokens
    };
  } catch (error) {
    logger.error('Session creation failed:', error);
    throw error;
  }
};

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', registerValidation, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const { fullName, email, phone, password, deviceInfo = {}, address = {} } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [
        { email: email.toLowerCase() },
        { phone: phone }
      ]
    });
    
    if (existingUser) {
      let message = 'User already exists';
      if (existingUser.email === email.toLowerCase()) {
        message = 'An account with this email already exists';
      } else if (existingUser.phone === phone) {
        message = 'An account with this phone number already exists';
      }
      
      return res.status(400).json({
        error: 'Registration failed',
        message
      });
    }
    
    // Create new user
    const userData = {
      fullName: fullName.trim(),
      email: email.toLowerCase(),
      phone,
      password,
      address,
      verificationToken: crypto.randomBytes(32).toString('hex')
    };
    
    const user = new User(userData);
    await user.save();
    
    // Log registration event
    Analytics.logEvent({
      userId: user._id,
      eventType: 'user_registration',
      eventAction: 'account_created',
      eventCategory: 'user_management',
      context: {
        device: deviceInfo,
        location: {
          ipAddress: req.ip
        }
      },
      metadata: {
        userAgent: req.get('User-Agent'),
        source: 'mobile_app'
      }
    });
    
    logger.logUserActivity(user._id, 'user_registered', {
      email: user.email,
      phone: user.phone
    });
    
    // Create session and generate tokens
    const locationInfo = {
      ipAddress: req.ip,
      country: req.headers['x-country'],
      state: req.headers['x-state'],
      city: req.headers['x-city']
    };
    
    const { session, tokens } = await createUserSession(user, deviceInfo, locationInfo);
    
    // Prepare response (exclude sensitive data)
    const userResponse = {
      id: user._id,
      fullName: user.fullName,
      email: user.email,
      phone: user.phone,
      isVerified: user.isVerified,
      profilePhoto: user.profilePhoto,
      settings: user.settings,
      createdAt: user.createdAt
    };
    
    res.status(201).json({
      message: 'Registration successful',
      user: userResponse,
      tokens,
      sessionId: session.sessionId
    });
    
  } catch (error) {
    logger.error('Registration error:', error);
    
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(400).json({
        error: 'Registration failed',
        message: `An account with this ${field} already exists`
      });
    }
    
    res.status(500).json({
      error: 'Server error',
      message: 'Registration failed. Please try again.'
    });
  }
});

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', loginValidation, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const { emailOrPhone, password, deviceInfo = {}, rememberMe = false } = req.body;
    
    // Find user by credentials
    const user = await User.findByCredentials(emailOrPhone, password);
    
    // Create session and generate tokens
    const locationInfo = {
      ipAddress: req.ip,
      country: req.headers['x-country'],
      state: req.headers['x-state'],
      city: req.headers['x-city']
    };
    
    const { session, tokens } = await createUserSession(user, deviceInfo, locationInfo);
    
    // Log login event
    Analytics.logEvent({
      userId: user._id,
      sessionId: session.sessionId,
      eventType: 'user_login',
      eventAction: 'login_success',
      eventCategory: 'user_management',
      context: {
        device: deviceInfo,
        location: locationInfo
      },
      metadata: {
        userAgent: req.get('User-Agent'),
        source: 'mobile_app'
      }
    });
    
    logger.logUserActivity(user._id, 'user_logged_in', {
      deviceType: deviceInfo.deviceType,
      ipAddress: req.ip,
      sessionId: session.sessionId
    });
    
    // Prepare response
    const userResponse = {
      id: user._id,
      fullName: user.fullName,
      email: user.email,
      phone: user.phone,
      isVerified: user.isVerified,
      profilePhoto: user.profilePhoto,
      settings: user.settings,
      address: user.address,
      farmingDetails: user.farmingDetails,
      lastLogin: user.lastLogin,
      loginCount: user.loginCount
    };
    
    res.json({
      message: 'Login successful',
      user: userResponse,
      tokens,
      sessionId: session.sessionId
    });
    
  } catch (error) {
    logger.error('Login error:', error);
    
    // Log failed login attempt
    Analytics.logEvent({
      eventType: 'user_login',
      eventAction: 'login_failed',
      eventCategory: 'security',
      eventData: {
        emailOrPhone,
        reason: error.message
      },
      context: {
        location: {
          ipAddress: req.ip
        }
      },
      status: 'failure',
      error: {
        message: error.message,
        severity: 'medium'
      }
    });
    
    res.status(401).json({
      error: 'Login failed',
      message: 'Invalid credentials'
    });
  }
});

// @route   POST /api/auth/logout
// @desc    Logout user
// @access  Private
router.post('/logout', verifyToken, async (req, res) => {
  try {
    // Terminate current session
    await req.session.terminate('user_logout');
    
    // Log logout event
    Analytics.logEvent({
      userId: req.user._id,
      sessionId: req.session.sessionId,
      eventType: 'user_logout',
      eventAction: 'logout_success',
      eventCategory: 'user_management',
      context: {
        location: {
          ipAddress: req.ip
        }
      }
    });
    
    logger.logUserActivity(req.user._id, 'user_logged_out', {
      sessionId: req.session.sessionId
    });
    
    res.json({
      message: 'Logout successful'
    });
    
  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Logout failed'
    });
  }
});

// @route   POST /api/auth/refresh
// @desc    Refresh access token
// @access  Public
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({
        error: 'Refresh token required',
        message: 'Please provide a refresh token'
      });
    }
    
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    
    // Find the session
    const session = await LoginSession.findOne({
      sessionId: decoded.sessionId,
      userId: decoded.userId,
      refreshToken: refreshToken,
      isActive: true
    }).populate('userId', '-password');
    
    if (!session) {
      return res.status(401).json({
        error: 'Invalid refresh token',
        message: 'Session not found or expired'
      });
    }
    
    // Generate new tokens
    const newTokens = session.generateTokens();
    await session.save();
    
    res.json({
      message: 'Tokens refreshed successfully',
      tokens: newTokens
    });
    
  } catch (error) {
    logger.error('Token refresh error:', error);
    
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Invalid refresh token',
        message: 'Token verification failed'
      });
    }
    
    res.status(500).json({
      error: 'Server error',
      message: 'Token refresh failed'
    });
  }
});

// @route   GET /api/auth/me
// @desc    Get current user profile
// @access  Private
router.get('/me', verifyToken, async (req, res) => {
  try {
    const userResponse = {
      id: req.user._id,
      fullName: req.user.fullName,
      email: req.user.email,
      phone: req.user.phone,
      isVerified: req.user.isVerified,
      profilePhoto: req.user.profilePhoto,
      settings: req.user.settings,
      address: req.user.address,
      farmingDetails: req.user.farmingDetails,
      lastLogin: req.user.lastLogin,
      loginCount: req.user.loginCount,
      createdAt: req.user.createdAt
    };
    
    res.json({
      user: userResponse,
      session: {
        sessionId: req.session.sessionId,
        loginTime: req.session.loginTime,
        lastActivity: req.session.lastActivity,
        deviceInfo: req.session.deviceInfo
      }
    });
    
  } catch (error) {
    logger.error('Get user profile error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to fetch user profile'
    });
  }
});

// @route   POST /api/auth/change-password
// @desc    Change user password
// @access  Private
router.post('/change-password', [
  verifyToken,
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('New password must contain at least one uppercase letter, one lowercase letter, and one number')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const { currentPassword, newPassword } = req.body;
    
    // Verify current password
    const isMatch = await req.user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({
        error: 'Password change failed',
        message: 'Current password is incorrect'
      });
    }
    
    // Update password
    req.user.password = newPassword;
    await req.user.save();
    
    // Terminate all other sessions for security
    await LoginSession.updateMany(
      { 
        userId: req.user._id,
        sessionId: { $ne: req.session.sessionId },
        isActive: true
      },
      {
        $set: {
          isActive: false,
          terminationReason: 'password_changed',
          logoutTime: new Date()
        }
      }
    );
    
    // Log password change
    Analytics.logEvent({
      userId: req.user._id,
      sessionId: req.session.sessionId,
      eventType: 'password_change',
      eventAction: 'password_updated',
      eventCategory: 'security',
      context: {
        location: {
          ipAddress: req.ip
        }
      }
    });
    
    logger.logSecurityEvent('password_changed', {
      userId: req.user._id,
      ipAddress: req.ip
    });
    
    res.json({
      message: 'Password changed successfully'
    });
    
  } catch (error) {
    logger.error('Password change error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Password change failed'
    });
  }
});

module.exports = router;