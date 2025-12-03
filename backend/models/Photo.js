const mongoose = require('mongoose');

const PhotoSchema = new mongoose.Schema({
  // User and Reference Information
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User ID is required']
  },
  
  cropId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Crop',
    required: false // Some photos might not be crop-specific
  },
  
  // File Information
  filename: {
    type: String,
    required: [true, 'Filename is required']
  },
  
  originalName: {
    type: String,
    required: [true, 'Original filename is required']
  },
  
  mimeType: {
    type: String,
    required: [true, 'MIME type is required'],
    enum: ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif']
  },
  
  fileSize: {
    type: Number,
    required: [true, 'File size is required'],
    min: [1, 'File size must be greater than 0']
  },
  
  // Storage Information
  storageType: {
    type: String,
    enum: ['gridfs', 'local', 'firebase', 's3'],
    default: 'gridfs'
  },
  
  gridfsId: {
    type: mongoose.Schema.Types.ObjectId,
    required: false // Only for GridFS storage
  },
  
  filePath: {
    type: String,
    required: false // For local storage
  },
  
  url: {
    type: String,
    required: false // Public URL if available
  },
  
  // Photo Metadata
  photoType: {
    type: String,
    enum: [
      'profile_photo',
      'crop_field',
      'crop_damage',
      'disease_symptom',
      'pest_damage',
      'growth_stage',
      'harvest',
      'weather_damage',
      'soil_condition',
      'equipment',
      'document',
      'other'
    ],
    required: [true, 'Photo type is required']
  },
  
  description: {
    type: String,
    maxlength: [500, 'Description cannot exceed 500 characters'],
    required: false
  },
  
  tags: [{
    type: String,
    trim: true
  }],
  
  // Location and Context
  location: {
    coordinates: {
      latitude: { type: Number, required: false },
      longitude: { type: Number, required: false }
    },
    address: {
      type: String,
      required: false
    },
    gpsAccuracy: {
      type: Number, // in meters
      required: false
    }
  },
  
  // Image Technical Details
  imageMetadata: {
    width: { type: Number, required: false },
    height: { type: Number, required: false },
    resolution: { type: String, required: false },
    colorSpace: { type: String, required: false },
    compression: { type: String, required: false },
    camera: {
      make: { type: String, required: false },
      model: { type: String, required: false },
      lens: { type: String, required: false }
    },
    exif: {
      iso: { type: Number, required: false },
      aperture: { type: String, required: false },
      shutterSpeed: { type: String, required: false },
      focalLength: { type: String, required: false },
      flash: { type: Boolean, required: false }
    }
  },
  
  // AI Analysis Results
  aiAnalysis: {
    processed: {
      type: Boolean,
      default: false
    },
    processedAt: {
      type: Date,
      required: false
    },
    
    // Disease Detection
    diseaseDetection: {
      detected: { type: Boolean, default: false },
      diseases: [{
        name: String,
        confidence: Number,
        severity: {
          type: String,
          enum: ['Low', 'Moderate', 'High', 'Severe']
        },
        recommendation: String
      }]
    },
    
    // Pest Detection
    pestDetection: {
      detected: { type: Boolean, default: false },
      pests: [{
        name: String,
        confidence: Number,
        count: Number,
        severity: {
          type: String,
          enum: ['Low', 'Moderate', 'High', 'Severe']
        }
      }]
    },
    
    // Crop Health Assessment
    healthAssessment: {
      overallHealth: {
        type: String,
        enum: ['Excellent', 'Good', 'Fair', 'Poor', 'Critical']
      },
      healthScore: {
        type: Number,
        min: 0,
        max: 100
      },
      indicators: [{
        parameter: String, // e.g., 'leaf_color', 'growth_rate', 'density'
        value: String,
        score: Number
      }]
    },
    
    // Object Detection
    objects: [{
      class: String,
      confidence: Number,
      boundingBox: {
        x: Number,
        y: Number,
        width: Number,
        height: Number
      }
    }],
    
    // Quality Assessment
    imageQuality: {
      sharpness: { type: Number, min: 0, max: 1 },
      brightness: { type: Number, min: 0, max: 1 },
      contrast: { type: Number, min: 0, max: 1 },
      overallQuality: {
        type: String,
        enum: ['Excellent', 'Good', 'Fair', 'Poor']
      }
    }
  },
  
  // Processing Status
  processingStatus: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed'],
    default: 'pending'
  },
  
  processingError: {
    type: String,
    required: false
  },
  
  // Access Control
  isPublic: {
    type: Boolean,
    default: false
  },
  
  sharedWith: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    permission: {
      type: String,
      enum: ['view', 'edit', 'download'],
      default: 'view'
    },
    sharedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Status and Flags
  isDeleted: {
    type: Boolean,
    default: false
  },
  
  deletedAt: {
    type: Date,
    required: false
  },
  
  isReported: {
    type: Boolean,
    default: false
  },
  
  reportReason: {
    type: String,
    required: false
  },
  
  // Usage Tracking
  viewCount: {
    type: Number,
    default: 0
  },
  
  downloadCount: {
    type: Number,
    default: 0
  },
  
  lastAccessed: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for better query performance
PhotoSchema.index({ userId: 1 });
PhotoSchema.index({ cropId: 1 });
PhotoSchema.index({ photoType: 1 });
PhotoSchema.index({ 'aiAnalysis.processed': 1 });
PhotoSchema.index({ processingStatus: 1 });
PhotoSchema.index({ isDeleted: 1 });
PhotoSchema.index({ createdAt: -1 });
PhotoSchema.index({ tags: 1 });
PhotoSchema.index({ gridfsId: 1 });

// Virtual for file size in human readable format
PhotoSchema.virtual('fileSizeFormatted').get(function() {
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  if (this.fileSize === 0) return '0 Bytes';
  
  const i = Math.floor(Math.log(this.fileSize) / Math.log(1024));
  return Math.round(this.fileSize / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
});

// Virtual for image aspect ratio
PhotoSchema.virtual('aspectRatio').get(function() {
  if (this.imageMetadata?.width && this.imageMetadata?.height) {
    return (this.imageMetadata.width / this.imageMetadata.height).toFixed(2);
  }
  return null;
});

// Method to increment view count
PhotoSchema.methods.incrementView = function() {
  this.viewCount += 1;
  this.lastAccessed = new Date();
  return this.save();
};

// Method to increment download count
PhotoSchema.methods.incrementDownload = function() {
  this.downloadCount += 1;
  this.lastAccessed = new Date();
  return this.save();
};

// Method to soft delete
PhotoSchema.methods.softDelete = function() {
  this.isDeleted = true;
  this.deletedAt = new Date();
  return this.save();
};

// Method to share photo
PhotoSchema.methods.shareWith = function(userId, permission = 'view') {
  // Check if already shared with this user
  const existingShare = this.sharedWith.find(
    share => share.userId.toString() === userId.toString()
  );
  
  if (existingShare) {
    existingShare.permission = permission;
    existingShare.sharedAt = new Date();
  } else {
    this.sharedWith.push({ userId, permission });
  }
  
  return this.save();
};

// Method to update AI analysis
PhotoSchema.methods.updateAIAnalysis = function(analysisData) {
  this.aiAnalysis = { ...this.aiAnalysis.toObject(), ...analysisData };
  this.aiAnalysis.processed = true;
  this.aiAnalysis.processedAt = new Date();
  this.processingStatus = 'completed';
  
  return this.save();
};

// Static method to find photos needing AI processing
PhotoSchema.statics.findUnprocessedPhotos = function(limit = 10) {
  return this.find({
    processingStatus: 'pending',
    'aiAnalysis.processed': false,
    isDeleted: false
  }).limit(limit).sort({ createdAt: 1 });
};

// Static method to get user's photo statistics
PhotoSchema.statics.getUserPhotoStats = async function(userId) {
  const stats = await this.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        isDeleted: false
      }
    },
    {
      $group: {
        _id: '$photoType',
        count: { $sum: 1 },
        totalSize: { $sum: '$fileSize' },
        avgSize: { $avg: '$fileSize' }
      }
    }
  ]);
  
  return stats;
};

module.exports = mongoose.model('Photo', PhotoSchema);