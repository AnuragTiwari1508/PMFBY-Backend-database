const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  // Basic Information
  fullName: {
    type: String,
    required: [true, 'Full name is required'],
    trim: true,
    maxlength: [100, 'Name cannot exceed 100 characters']
  },
  
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please provide a valid email']
  },
  
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    unique: true,
    match: [/^[6-9]\d{9}$/, 'Please provide a valid 10-digit Indian mobile number']
  },
  
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters']
  },
  
  // Profile Information
  profilePhoto: {
    type: String, // URL or file path
    default: null
  },
  
  aadhaarNumber: {
    type: String,
    unique: true,
    sparse: true, // Allows null values while maintaining uniqueness
    match: [/^\d{12}$/, 'Aadhaar number must be 12 digits']
  },
  
  dateOfBirth: {
    type: Date,
    required: false
  },
  
  gender: {
    type: String,
    enum: ['Male', 'Female', 'Other'],
    required: false
  },
  
  // Address Information
  address: {
    village: { type: String, required: false },
    district: { type: String, required: false },
    state: { type: String, required: false },
    pincode: {
      type: String,
      match: [/^\d{6}$/, 'Pincode must be 6 digits']
    },
    coordinates: {
      latitude: { type: Number, required: false },
      longitude: { type: Number, required: false }
    }
  },
  
  // Farming Information
  farmingDetails: {
    totalLandArea: { type: Number, required: false }, // in acres
    landOwnershipType: {
      type: String,
      enum: ['Owner', 'Tenant', 'Sharecropper'],
      required: false
    },
    bankAccountNumber: { type: String, required: false },
    ifscCode: { type: String, required: false },
    kccNumber: { type: String, required: false }, // Kisan Credit Card
    soilType: {
      type: String,
      enum: ['Clay', 'Sandy', 'Loamy', 'Silty', 'Other'],
      required: false
    }
  },
  
  // App Settings
  settings: {
    language: {
      type: String,
      enum: ['en', 'hi', 'bn', 'te', 'ta', 'mr', 'gu', 'kn', 'or', 'pa'],
      default: 'en'
    },
    notifications: {
      email: { type: Boolean, default: true },
      sms: { type: Boolean, default: true },
      push: { type: Boolean, default: true }
    },
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'light'
    }
  },
  
  // Account Status
  isActive: {
    type: Boolean,
    default: true
  },
  
  isVerified: {
    type: Boolean,
    default: false
  },
  
  verificationToken: {
    type: String,
    required: false
  },
  
  passwordResetToken: {
    type: String,
    required: false
  },
  
  passwordResetExpires: {
    type: Date,
    required: false
  },
  
  // Tracking
  lastLogin: {
    type: Date,
    default: Date.now
  },
  
  loginCount: {
    type: Number,
    default: 0
  },
  
  deviceInfo: {
    deviceId: { type: String, required: false },
    deviceType: {
      type: String,
      enum: ['Android', 'iOS', 'Web'],
      required: false
    },
    appVersion: { type: String, required: false },
    fcmToken: { type: String, required: false } // For push notifications
  }
}, {
  timestamps: true, // Automatically adds createdAt and updatedAt
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Index for better query performance
UserSchema.index({ email: 1 });
UserSchema.index({ phone: 1 });
UserSchema.index({ aadhaarNumber: 1 });
UserSchema.index({ 'address.district': 1, 'address.state': 1 });

// Virtual for age calculation
UserSchema.virtual('age').get(function() {
  if (this.dateOfBirth) {
    const today = new Date();
    const birthDate = new Date(this.dateOfBirth);
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }
    return age;
  }
  return null;
});

// Pre-save middleware to hash password
UserSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Hash password with cost of 12
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Method to generate password reset token
UserSchema.methods.createPasswordResetToken = function() {
  const crypto = require('crypto');
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
    
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  return resetToken;
};

// Method to update login tracking
UserSchema.methods.updateLoginTracking = function(deviceInfo = {}) {
  this.lastLogin = new Date();
  this.loginCount += 1;
  
  if (deviceInfo.deviceId) this.deviceInfo.deviceId = deviceInfo.deviceId;
  if (deviceInfo.deviceType) this.deviceInfo.deviceType = deviceInfo.deviceType;
  if (deviceInfo.appVersion) this.deviceInfo.appVersion = deviceInfo.appVersion;
  if (deviceInfo.fcmToken) this.deviceInfo.fcmToken = deviceInfo.fcmToken;
  
  return this.save();
};

// Static method to find by credentials
UserSchema.statics.findByCredentials = async function(emailOrPhone, password) {
  const user = await this.findOne({
    $or: [
      { email: emailOrPhone.toLowerCase() },
      { phone: emailOrPhone }
    ],
    isActive: true
  });
  
  if (!user) {
    throw new Error('Invalid login credentials');
  }
  
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    throw new Error('Invalid login credentials');
  }
  
  return user;
};

module.exports = mongoose.model('User', UserSchema);