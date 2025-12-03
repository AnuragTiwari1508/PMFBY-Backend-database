const jwt = require('jsonwebtoken');
const User = require('../models/User');
const LoginSession = require('../models/LoginSession');
const Analytics = require('../models/Analytics');
const logger = require('../utils/logger');

// Verify JWT Token
const verifyToken = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '') || 
                  req.header('x-auth-token') ||
                  req.cookies?.token;
    
    if (!token) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'No authentication token provided'
      });
    }
    
    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Find the user
    const user = await User.findById(decoded.userId).select('-password');
    if (!user || !user.isActive) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'Invalid token or user not found'
      });
    }
    
    // Find the active session
    const session = await LoginSession.findOne({
      sessionId: decoded.sessionId,
      userId: decoded.userId,
      isActive: true
    });
    
    if (!session) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'Session not found or expired'
      });
    }
    
    // Update session activity
    await session.updateActivity({
      action: `${req.method} ${req.path}`,
      endpoint: req.originalUrl,
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip
    });
    
    // Attach user and session to request
    req.user = user;
    req.session = session;
    req.token = token;
    
    // Log user activity for analytics
    Analytics.logEvent({
      userId: user._id,
      sessionId: session.sessionId,
      eventType: 'api_call',
      eventAction: `${req.method} ${req.path}`,
      eventCategory: 'system',
      context: {
        device: {
          type: session.deviceInfo.deviceType,
          model: session.deviceInfo.deviceModel,
          appVersion: session.deviceInfo.appVersion
        },
        location: {
          ipAddress: req.ip
        },
        app: {
          currentScreen: req.headers['x-current-screen'],
          userRole: 'farmer', // Default role
          language: user.settings.language
        }
      },
      metadata: {
        userAgent: req.get('User-Agent'),
        source: 'mobile_app'
      }
    }).catch(err => logger.error('Analytics logging failed:', err));
    
    next();
    
  } catch (error) {
    logger.error('Token verification failed:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Access denied',
        message: 'Invalid token'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Access denied',
        message: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    return res.status(500).json({
      error: 'Server error',
      message: 'Token verification failed'
    });
  }
};

// Optional authentication (doesn't fail if no token)
const optionalAuth = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '') || 
                req.header('x-auth-token') ||
                req.cookies?.token;
  
  if (!token) {
    return next();
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (user && user.isActive) {
      req.user = user;
    }
  } catch (error) {
    // Continue without authentication
    logger.warn('Optional auth failed:', error.message);
  }
  
  next();
};

// Check if user is verified
const requireVerified = (req, res, next) => {
  if (!req.user.isVerified) {
    return res.status(403).json({
      error: 'Account not verified',
      message: 'Please verify your account to access this feature',
      code: 'ACCOUNT_NOT_VERIFIED'
    });
  }
  next();
};

// Role-based authorization
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'Authentication required'
      });
    }
    
    const userRole = req.user.role || 'farmer';
    
    if (!roles.includes(userRole)) {
      logger.logSecurityEvent('unauthorized_access_attempt', {
        userId: req.user._id,
        userRole,
        requiredRoles: roles,
        endpoint: req.originalUrl,
        ipAddress: req.ip
      });
      
      return res.status(403).json({
        error: 'Access denied',
        message: 'Insufficient permissions'
      });
    }
    
    next();
  };
};

// Rate limiting per user
const userRateLimit = (maxRequests = 100, windowMs = 15 * 60 * 1000) => {
  const requests = new Map();
  
  return (req, res, next) => {
    if (!req.user) {
      return next();
    }
    
    const userId = req.user._id.toString();
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Get user's request history
    let userRequests = requests.get(userId) || [];
    
    // Remove old requests outside the window
    userRequests = userRequests.filter(timestamp => timestamp > windowStart);
    
    // Check if user has exceeded the limit
    if (userRequests.length >= maxRequests) {
      logger.logSecurityEvent('rate_limit_exceeded', {
        userId,
        requestCount: userRequests.length,
        maxRequests,
        windowMs,
        ipAddress: req.ip
      });
      
      return res.status(429).json({
        error: 'Too many requests',
        message: `Rate limit exceeded. Maximum ${maxRequests} requests per ${windowMs / 1000} seconds`,
        retryAfter: Math.ceil((userRequests[0] + windowMs - now) / 1000)
      });
    }
    
    // Add current request
    userRequests.push(now);
    requests.set(userId, userRequests);
    
    // Clean up old entries periodically
    if (Math.random() < 0.01) { // 1% chance to clean up
      for (const [key, timestamps] of requests.entries()) {
        const filteredTimestamps = timestamps.filter(ts => ts > windowStart);
        if (filteredTimestamps.length === 0) {
          requests.delete(key);
        } else {
          requests.set(key, filteredTimestamps);
        }
      }
    }
    
    next();
  };
};

// Device validation
const validateDevice = async (req, res, next) => {
  try {
    const deviceId = req.headers['x-device-id'];
    
    if (!deviceId) {
      return res.status(400).json({
        error: 'Device validation failed',
        message: 'Device ID is required'
      });
    }
    
    // Check if the session's device matches the request device
    if (req.session && req.session.deviceInfo.deviceId !== deviceId) {
      logger.logSecurityEvent('device_mismatch', {
        userId: req.user._id,
        sessionDeviceId: req.session.deviceInfo.deviceId,
        requestDeviceId: deviceId,
        ipAddress: req.ip
      });
      
      // Terminate the session for security
      await req.session.terminate('device_change');
      
      return res.status(401).json({
        error: 'Device validation failed',
        message: 'Device mismatch detected. Please login again.',
        code: 'DEVICE_MISMATCH'
      });
    }
    
    next();
  } catch (error) {
    logger.error('Device validation error:', error);
    next();
  }
};

// Security headers middleware
const securityHeaders = (req, res, next) => {
  // Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  // Remove sensitive headers
  res.removeHeader('X-Powered-By');
  
  next();
};

// Suspicious activity detection
const detectSuspiciousActivity = async (req, res, next) => {
  try {
    if (!req.user || !req.session) {
      return next();
    }
    
    const suspiciousIndicators = [];
    
    // Check for unusual IP address
    const currentIP = req.ip;
    const sessionIP = req.session.loginLocation.ipAddress;
    
    if (currentIP !== sessionIP) {
      suspiciousIndicators.push('ip_address_change');
    }
    
    // Check for unusual user agent
    const currentUserAgent = req.get('User-Agent');
    const sessionUserAgent = req.session.deviceInfo.userAgent;
    
    if (currentUserAgent !== sessionUserAgent) {
      suspiciousIndicators.push('user_agent_change');
    }
    
    // Check for rapid API calls (more than 10 calls per minute)
    const recentActivity = req.session.activityLog.filter(
      activity => Date.now() - activity.timestamp.getTime() < 60000
    );
    
    if (recentActivity.length > 10) {
      suspiciousIndicators.push('rapid_api_calls');
    }
    
    // If suspicious activity detected
    if (suspiciousIndicators.length > 0) {
      await req.session.markSuspicious('multiple_indicators', {
        indicators: suspiciousIndicators,
        currentIP,
        currentUserAgent,
        endpoint: req.originalUrl
      });
      
      logger.logSecurityEvent('suspicious_activity_detected', {
        userId: req.user._id,
        sessionId: req.session.sessionId,
        indicators: suspiciousIndicators,
        ipAddress: currentIP,
        userAgent: currentUserAgent
      });
      
      // For now, just log and continue. You might want to terminate session or require re-authentication
    }
    
    next();
  } catch (error) {
    logger.error('Suspicious activity detection error:', error);
    next();
  }
};

module.exports = {
  verifyToken,
  optionalAuth,
  requireVerified,
  requireRole,
  userRateLimit,
  validateDevice,
  securityHeaders,
  detectSuspiciousActivity
};