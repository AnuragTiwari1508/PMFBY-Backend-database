const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const LoginSessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User ID is required']
  },
  
  // Session Information
  sessionId: {
    type: String,
    required: true,
    unique: true
  },
  
  accessToken: {
    type: String,
    required: true
  },
  
  refreshToken: {
    type: String,
    required: true
  },
  
  // Device and Location Information
  deviceInfo: {
    deviceId: {
      type: String,
      required: true
    },
    deviceType: {
      type: String,
      enum: ['Android', 'iOS', 'Web', 'Desktop'],
      required: true
    },
    deviceModel: {
      type: String,
      required: false
    },
    osVersion: {
      type: String,
      required: false
    },
    appVersion: {
      type: String,
      required: false
    },
    userAgent: {
      type: String,
      required: false
    }
  },
  
  // Network and Location
  loginLocation: {
    ipAddress: {
      type: String,
      required: true
    },
    country: {
      type: String,
      required: false
    },
    state: {
      type: String,
      required: false
    },
    city: {
      type: String,
      required: false
    },
    coordinates: {
      latitude: { type: Number, required: false },
      longitude: { type: Number, required: false }
    }
  },
  
  // Session Tracking
  loginTime: {
    type: Date,
    default: Date.now,
    required: true
  },
  
  lastActivity: {
    type: Date,
    default: Date.now,
    required: true
  },
  
  logoutTime: {
    type: Date,
    required: false
  },
  
  // Session Status
  isActive: {
    type: Boolean,
    default: true
  },
  
  terminationReason: {
    type: String,
    enum: ['user_logout', 'token_expired', 'admin_terminated', 'security_breach', 'device_change'],
    required: false
  },
  
  // Security Flags
  isSuspicious: {
    type: Boolean,
    default: false
  },
  
  suspiciousActivities: [{
    activity: {
      type: String,
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      required: false
    }
  }],
  
  // Activity Tracking
  activityLog: [{
    action: {
      type: String,
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    endpoint: {
      type: String,
      required: false
    },
    userAgent: {
      type: String,
      required: false
    },
    ipAddress: {
      type: String,
      required: false
    }
  }],
  
  // Session Statistics
  sessionDuration: {
    type: Number, // in milliseconds
    required: false
  },
  
  apiCallsCount: {
    type: Number,
    default: 0
  },
  
  // FCM Token for Push Notifications
  fcmToken: {
    type: String,
    required: false
  }
}, {
  timestamps: true
});

// Indexes for better query performance
LoginSessionSchema.index({ userId: 1 });
LoginSessionSchema.index({ sessionId: 1 });
LoginSessionSchema.index({ 'deviceInfo.deviceId': 1 });
LoginSessionSchema.index({ isActive: 1 });
LoginSessionSchema.index({ loginTime: -1 });
LoginSessionSchema.index({ lastActivity: -1 });
LoginSessionSchema.index({ accessToken: 1 });
LoginSessionSchema.index({ refreshToken: 1 });

// Virtual for session duration calculation
LoginSessionSchema.virtual('calculatedDuration').get(function() {
  if (this.logoutTime) {
    return this.logoutTime.getTime() - this.loginTime.getTime();
  } else if (this.isActive) {
    return Date.now() - this.loginTime.getTime();
  }
  return 0;
});

// Method to update last activity
LoginSessionSchema.methods.updateActivity = function(activityData = {}) {
  this.lastActivity = new Date();
  this.apiCallsCount += 1;
  
  if (activityData.action) {
    this.activityLog.push({
      action: activityData.action,
      endpoint: activityData.endpoint,
      userAgent: activityData.userAgent,
      ipAddress: activityData.ipAddress
    });
  }
  
  return this.save();
};

// Method to terminate session
LoginSessionSchema.methods.terminate = function(reason = 'user_logout') {
  this.isActive = false;
  this.logoutTime = new Date();
  this.terminationReason = reason;
  this.sessionDuration = this.logoutTime.getTime() - this.loginTime.getTime();
  
  return this.save();
};

// Method to mark as suspicious
LoginSessionSchema.methods.markSuspicious = function(activity, details = {}) {
  this.isSuspicious = true;
  this.suspiciousActivities.push({
    activity,
    details
  });
  
  return this.save();
};

// Method to generate new tokens
LoginSessionSchema.methods.generateTokens = function() {
  const accessTokenPayload = {
    userId: this.userId,
    sessionId: this.sessionId,
    deviceId: this.deviceInfo.deviceId,
    type: 'access'
  };
  
  const refreshTokenPayload = {
    userId: this.userId,
    sessionId: this.sessionId,
    deviceId: this.deviceInfo.deviceId,
    type: 'refresh'
  };
  
  const accessToken = jwt.sign(
    accessTokenPayload,
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE_TIME || '7d' }
  );
  
  const refreshToken = jwt.sign(
    refreshTokenPayload,
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRE_TIME || '30d' }
  );
  
  this.accessToken = accessToken;
  this.refreshToken = refreshToken;
  
  return { accessToken, refreshToken };
};

// Static method to find active sessions by user
LoginSessionSchema.statics.findActiveSessionsByUser = function(userId) {
  return this.find({
    userId,
    isActive: true
  }).sort({ lastActivity: -1 });
};

// Static method to cleanup expired sessions
LoginSessionSchema.statics.cleanupExpiredSessions = async function() {
  const expirationTime = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000)); // 7 days ago
  
  const result = await this.updateMany(
    {
      lastActivity: { $lt: expirationTime },
      isActive: true
    },
    {
      $set: {
        isActive: false,
        terminationReason: 'token_expired',
        logoutTime: new Date()
      }
    }
  );
  
  return result;
};

// Static method to find suspicious sessions
LoginSessionSchema.statics.findSuspiciousSessions = function() {
  return this.find({
    $or: [
      { isSuspicious: true },
      { 'suspiciousActivities.0': { $exists: true } }
    ],
    isActive: true
  }).populate('userId', 'fullName email phone');
};

// Pre-save middleware to generate session ID
LoginSessionSchema.pre('save', function(next) {
  if (this.isNew && !this.sessionId) {
    const crypto = require('crypto');
    this.sessionId = crypto.randomBytes(32).toString('hex');
  }
  next();
});

// Schedule cleanup of expired sessions (run every hour)
setInterval(async () => {
  try {
    const LoginSession = mongoose.model('LoginSession');
    await LoginSession.cleanupExpiredSessions();
  } catch (error) {
    console.error('Error cleaning up expired sessions:', error);
  }
}, 60 * 60 * 1000); // 1 hour

module.exports = mongoose.model('LoginSession', LoginSessionSchema);