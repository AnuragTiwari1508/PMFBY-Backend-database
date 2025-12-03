const mongoose = require('mongoose');

const AnalyticsSchema = new mongoose.Schema({
  // User and Session Information
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false // Some events might be anonymous
  },
  
  sessionId: {
    type: String,
    required: false
  },
  
  // Event Information
  eventType: {
    type: String,
    required: [true, 'Event type is required'],
    enum: [
      // User Actions
      'user_registration',
      'user_login',
      'user_logout',
      'profile_update',
      'password_change',
      
      // Crop Management
      'crop_created',
      'crop_updated',
      'crop_deleted',
      'crop_harvested',
      'growth_stage_updated',
      'weather_event_added',
      
      // Photo and Media
      'photo_uploaded',
      'photo_analyzed',
      'photo_shared',
      'photo_deleted',
      
      // Insurance and Claims
      'insurance_registered',
      'claim_filed',
      'claim_updated',
      'claim_approved',
      'claim_rejected',
      
      // AI/ML Interactions
      'ai_analysis_requested',
      'ai_analysis_completed',
      'disease_detected',
      'yield_predicted',
      'risk_assessed',
      
      // App Navigation and Usage
      'screen_viewed',
      'feature_accessed',
      'tutorial_completed',
      'help_accessed',
      'feedback_submitted',
      
      // System Events
      'api_call',
      'error_occurred',
      'performance_metric',
      'security_alert',
      
      // Business Intelligence
      'report_generated',
      'data_exported',
      'notification_sent',
      'notification_opened'
    ]
  },
  
  eventAction: {
    type: String,
    required: [true, 'Event action is required']
  },
  
  eventCategory: {
    type: String,
    required: [true, 'Event category is required'],
    enum: [
      'user_management',
      'crop_management',
      'photo_management',
      'insurance',
      'ai_ml',
      'navigation',
      'system',
      'business_intelligence',
      'security',
      'performance'
    ]
  },
  
  // Event Details
  eventData: {
    type: mongoose.Schema.Types.Mixed,
    required: false
  },
  
  // Context Information
  context: {
    // Device Information
    device: {
      type: {
        type: String,
        enum: ['Android', 'iOS', 'Web', 'Desktop']
      },
      model: String,
      osVersion: String,
      appVersion: String,
      screenSize: String
    },
    
    // Location Information
    location: {
      country: String,
      state: String,
      city: String,
      coordinates: {
        latitude: Number,
        longitude: Number
      },
      ipAddress: String
    },
    
    // Network Information
    network: {
      type: {
        type: String,
        enum: ['wifi', 'cellular', '4g', '5g', 'ethernet']
      },
      provider: String,
      speed: String
    },
    
    // App Context
    app: {
      currentScreen: String,
      previousScreen: String,
      userRole: String,
      language: String,
      theme: String
    }
  },
  
  // Timing Information
  timestamp: {
    type: Date,
    default: Date.now,
    required: true
  },
  
  duration: {
    type: Number, // in milliseconds
    required: false
  },
  
  // Performance Metrics
  performance: {
    loadTime: Number, // in milliseconds
    responseTime: Number,
    memoryUsage: Number,
    cpuUsage: Number,
    batteryLevel: Number,
    networkLatency: Number
  },
  
  // Error Information (if applicable)
  error: {
    message: String,
    stack: String,
    code: String,
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical']
    }
  },
  
  // Success/Failure Status
  status: {
    type: String,
    enum: ['success', 'failure', 'partial', 'pending'],
    default: 'success'
  },
  
  // Additional Metadata
  metadata: {
    referrer: String,
    userAgent: String,
    requestId: String,
    correlationId: String,
    source: {
      type: String,
      enum: ['mobile_app', 'web_app', 'api', 'background_job', 'webhook']
    }
  },
  
  // Aggregation Fields (for performance)
  aggregationFields: {
    hour: { type: Number, min: 0, max: 23 },
    dayOfWeek: { type: Number, min: 0, max: 6 },
    dayOfMonth: { type: Number, min: 1, max: 31 },
    month: { type: Number, min: 1, max: 12 },
    year: { type: Number, min: 2024 },
    quarter: { type: Number, min: 1, max: 4 }
  },
  
  // Privacy and Retention
  isPersonalData: {
    type: Boolean,
    default: false
  },
  
  retentionDays: {
    type: Number,
    default: 90 // Default retention period
  },
  
  // Processing Status
  processed: {
    type: Boolean,
    default: false
  },
  
  processedAt: {
    type: Date,
    required: false
  }
}, {
  timestamps: true
});

// Indexes for better query performance
AnalyticsSchema.index({ userId: 1 });
AnalyticsSchema.index({ eventType: 1 });
AnalyticsSchema.index({ eventCategory: 1 });
AnalyticsSchema.index({ timestamp: -1 });
AnalyticsSchema.index({ sessionId: 1 });
AnalyticsSchema.index({ 'aggregationFields.year': 1, 'aggregationFields.month': 1 });
AnalyticsSchema.index({ 'aggregationFields.dayOfWeek': 1, 'aggregationFields.hour': 1 });
AnalyticsSchema.index({ 'context.device.type': 1 });
AnalyticsSchema.index({ 'context.location.country': 1, 'context.location.state': 1 });
AnalyticsSchema.index({ processed: 1 });
AnalyticsSchema.index({ status: 1 });

// Pre-save middleware to populate aggregation fields
AnalyticsSchema.pre('save', function(next) {
  if (this.isNew) {
    const date = this.timestamp || new Date();
    
    this.aggregationFields = {
      hour: date.getHours(),
      dayOfWeek: date.getDay(),
      dayOfMonth: date.getDate(),
      month: date.getMonth() + 1,
      year: date.getFullYear(),
      quarter: Math.ceil((date.getMonth() + 1) / 3)
    };
  }
  next();
});

// Static method to log event
AnalyticsSchema.statics.logEvent = function(eventData) {
  const event = new this(eventData);
  return event.save();
};

// Static method to get user activity summary
AnalyticsSchema.statics.getUserActivitySummary = async function(userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  const summary = await this.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        timestamp: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: {
          date: {
            $dateToString: {
              format: '%Y-%m-%d',
              date: '$timestamp'
            }
          },
          eventCategory: '$eventCategory'
        },
        count: { $sum: 1 }
      }
    },
    {
      $sort: { '_id.date': -1 }
    }
  ]);
  
  return summary;
};

// Static method to get app usage statistics
AnalyticsSchema.statics.getAppUsageStats = async function(days = 7) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  const stats = await this.aggregate([
    {
      $match: {
        timestamp: { $gte: startDate },
        eventType: { $in: ['user_login', 'screen_viewed', 'feature_accessed'] }
      }
    },
    {
      $group: {
        _id: {
          date: {
            $dateToString: {
              format: '%Y-%m-%d',
              date: '$timestamp'
            }
          }
        },
        uniqueUsers: { $addToSet: '$userId' },
        totalEvents: { $sum: 1 },
        avgDuration: { $avg: '$duration' }
      }
    },
    {
      $project: {
        date: '$_id.date',
        uniqueUsers: { $size: '$uniqueUsers' },
        totalEvents: 1,
        avgDuration: { $round: ['$avgDuration', 2] }
      }
    },
    {
      $sort: { date: -1 }
    }
  ]);
  
  return stats;
};

// Static method to get error statistics
AnalyticsSchema.statics.getErrorStats = async function(days = 7) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  const errorStats = await this.aggregate([
    {
      $match: {
        timestamp: { $gte: startDate },
        status: 'failure'
      }
    },
    {
      $group: {
        _id: {
          errorCode: '$error.code',
          severity: '$error.severity'
        },
        count: { $sum: 1 },
        lastOccurred: { $max: '$timestamp' }
      }
    },
    {
      $sort: { count: -1 }
    }
  ]);
  
  return errorStats;
};

// Static method to cleanup old analytics data
AnalyticsSchema.statics.cleanupOldData = async function() {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - 90); // Default 90 days retention
  
  const result = await this.deleteMany({
    timestamp: { $lt: cutoffDate },
    isPersonalData: false
  });
  
  return result;
};

module.exports = mongoose.model('Analytics', AnalyticsSchema);