const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Photo = require('../models/Photo');
const Crop = require('../models/Crop');
const LoginSession = require('../models/LoginSession');
const Analytics = require('../models/Analytics');
const { verifyToken, requireVerified } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// @route   GET /api/users/profile
// @desc    Get current user's detailed profile
// @access  Private
router.get('/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password -passwordResetToken -passwordResetExpires -verificationToken');
    
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User profile not found'
      });
    }
    
    // Get additional statistics
    const [photoCount, cropCount, activeSessionsCount] = await Promise.all([
      Photo.countDocuments({ userId: user._id, isDeleted: false }),
      Crop.countDocuments({ userId: user._id }),
      LoginSession.countDocuments({ userId: user._id, isActive: true })
    ]);
    
    const profileData = {
      ...user.toObject(),
      statistics: {
        photosUploaded: photoCount,
        cropsRegistered: cropCount,
        activeSessions: activeSessionsCount,
        accountAge: Math.floor((Date.now() - user.createdAt) / (1000 * 60 * 60 * 24)) // days
      }
    };
    
    res.json({
      profile: profileData
    });
    
  } catch (error) {
    logger.error('Get profile error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to retrieve profile'
    });
  }
});

// @route   PUT /api/users/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', [
  verifyToken,
  body('fullName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Full name must be between 2 and 100 characters'),
    
  body('phone')
    .optional()
    .matches(/^[6-9]\d{9}$/)
    .withMessage('Please provide a valid 10-digit Indian mobile number'),
    
  body('address.village')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Village name cannot exceed 100 characters'),
    
  body('address.district')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('District name cannot exceed 100 characters'),
    
  body('address.state')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('State name cannot exceed 100 characters'),
    
  body('address.pincode')
    .optional()
    .matches(/^\d{6}$/)
    .withMessage('Pincode must be 6 digits')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const {
      fullName,
      phone,
      dateOfBirth,
      gender,
      address,
      farmingDetails,
      settings
    } = req.body;
    
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User not found'
      });
    }
    
    // Check if phone number is being changed and if it's already in use
    if (phone && phone !== user.phone) {
      const existingUser = await User.findOne({ phone, _id: { $ne: user._id } });
      if (existingUser) {
        return res.status(400).json({
          error: 'Phone number already exists',
          message: 'This phone number is already registered with another account'
        });
      }
    }
    
    // Update fields
    if (fullName) user.fullName = fullName.trim();
    if (phone) user.phone = phone;
    if (dateOfBirth) user.dateOfBirth = new Date(dateOfBirth);
    if (gender) user.gender = gender;
    
    // Update address
    if (address) {
      user.address = {
        ...user.address.toObject(),
        ...address
      };
    }
    
    // Update farming details
    if (farmingDetails) {
      user.farmingDetails = {
        ...user.farmingDetails.toObject(),
        ...farmingDetails
      };
    }
    
    // Update settings
    if (settings) {
      user.settings = {
        ...user.settings.toObject(),
        ...settings
      };
    }
    
    await user.save();
    
    // Log profile update
    Analytics.logEvent({
      userId: user._id,
      sessionId: req.session?.sessionId,
      eventType: 'profile_update',
      eventAction: 'profile_updated',
      eventCategory: 'user_management',
      eventData: {
        fieldsUpdated: Object.keys(req.body)
      }
    });
    
    logger.logUserActivity(user._id, 'profile_updated', {
      fieldsUpdated: Object.keys(req.body)
    });
    
    // Return updated profile (excluding sensitive data)
    const updatedProfile = await User.findById(user._id)
      .select('-password -passwordResetToken -passwordResetExpires -verificationToken');
    
    res.json({
      message: 'Profile updated successfully',
      profile: updatedProfile
    });
    
  } catch (error) {
    logger.error('Profile update error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to update profile'
    });
  }
});

// @route   GET /api/users/dashboard
// @desc    Get user dashboard data
// @access  Private
router.get('/dashboard', verifyToken, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get dashboard statistics
    const [crops, recentPhotos, analytics] = await Promise.all([
      Crop.find({ userId })
        .sort({ createdAt: -1 })
        .limit(5)
        .populate('userId', 'fullName'),
        
      Photo.find({ userId, isDeleted: false })
        .sort({ createdAt: -1 })
        .limit(10)
        .select('filename originalName photoType createdAt url'),
        
      Analytics.getUserActivitySummary(userId, 7) // Last 7 days
    ]);
    
    // Calculate crop statistics
    const cropStats = await Crop.aggregate([
      { $match: { userId: userId } },
      {
        $group: {
          _id: '$cropStatus',
          count: { $sum: 1 },
          totalArea: { $sum: '$landDetails.areaInAcres' }
        }
      }
    ]);
    
    // Calculate photo statistics
    const photoStats = await Photo.aggregate([
      { $match: { userId: userId, isDeleted: false } },
      {
        $group: {
          _id: '$photoType',
          count: { $sum: 1 },
          totalSize: { $sum: '$fileSize' }
        }
      }
    ]);
    
    // Get recent weather events
    const recentWeatherEvents = await Crop.aggregate([
      { $match: { userId: userId } },
      { $unwind: '$weatherEvents' },
      { $sort: { 'weatherEvents.date': -1 } },
      { $limit: 5 },
      {
        $project: {
          cropName: 1,
          event: '$weatherEvents'
        }
      }
    ]);
    
    // Add URLs to recent photos
    const photosWithUrls = recentPhotos.map(photo => ({
      ...photo.toObject(),
      url: `/api/upload/photo/${photo._id}`
    }));
    
    const dashboardData = {
      user: {
        fullName: req.user.fullName,
        email: req.user.email,
        profilePhoto: req.user.profilePhoto,
        lastLogin: req.user.lastLogin
      },
      statistics: {
        crops: {
          total: crops.length,
          byStatus: cropStats,
          recent: crops
        },
        photos: {
          total: recentPhotos.length,
          byType: photoStats,
          recent: photosWithUrls
        },
        activity: analytics
      },
      recentWeatherEvents,
      notifications: {
        // You can add notification logic here
        unread: 0,
        recent: []
      }
    };
    
    res.json({
      dashboard: dashboardData
    });
    
  } catch (error) {
    logger.error('Dashboard data error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to load dashboard data'
    });
  }
});

// @route   GET /api/users/sessions
// @desc    Get user's active sessions
// @access  Private
router.get('/sessions', verifyToken, async (req, res) => {
  try {
    const sessions = await LoginSession.findActiveSessionsByUser(req.user._id);
    
    const sessionData = sessions.map(session => ({
      sessionId: session.sessionId,
      deviceInfo: session.deviceInfo,
      loginLocation: session.loginLocation,
      loginTime: session.loginTime,
      lastActivity: session.lastActivity,
      isCurrent: session.sessionId === req.session?.sessionId,
      duration: session.calculatedDuration
    }));
    
    res.json({
      sessions: sessionData,
      total: sessionData.length
    });
    
  } catch (error) {
    logger.error('Get sessions error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to retrieve sessions'
    });
  }
});

// @route   DELETE /api/users/sessions/:sessionId
// @desc    Terminate a specific session
// @access  Private
router.delete('/sessions/:sessionId', verifyToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    // Find the session
    const session = await LoginSession.findOne({
      sessionId,
      userId: req.user._id,
      isActive: true
    });
    
    if (!session) {
      return res.status(404).json({
        error: 'Session not found',
        message: 'Session not found or already terminated'
      });
    }
    
    // Prevent terminating current session
    if (session.sessionId === req.session?.sessionId) {
      return res.status(400).json({
        error: 'Cannot terminate current session',
        message: 'Use logout to terminate your current session'
      });
    }
    
    // Terminate the session
    await session.terminate('admin_terminated');
    
    // Log session termination
    Analytics.logEvent({
      userId: req.user._id,
      sessionId: req.session?.sessionId,
      eventType: 'session_terminated',
      eventAction: 'remote_logout',
      eventCategory: 'security',
      eventData: {
        terminatedSessionId: sessionId,
        deviceType: session.deviceInfo.deviceType
      }
    });
    
    logger.logSecurityEvent('session_terminated_remotely', {
      userId: req.user._id,
      terminatedSessionId: sessionId,
      ipAddress: req.ip
    });
    
    res.json({
      message: 'Session terminated successfully'
    });
    
  } catch (error) {
    logger.error('Session termination error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to terminate session'
    });
  }
});

// @route   DELETE /api/users/sessions
// @desc    Terminate all other sessions except current
// @access  Private
router.delete('/sessions', verifyToken, async (req, res) => {
  try {
    // Terminate all other sessions
    const result = await LoginSession.updateMany(
      {
        userId: req.user._id,
        sessionId: { $ne: req.session?.sessionId },
        isActive: true
      },
      {
        $set: {
          isActive: false,
          terminationReason: 'admin_terminated',
          logoutTime: new Date()
        }
      }
    );
    
    // Log mass session termination
    Analytics.logEvent({
      userId: req.user._id,
      sessionId: req.session?.sessionId,
      eventType: 'session_terminated',
      eventAction: 'logout_all_devices',
      eventCategory: 'security',
      eventData: {
        terminatedCount: result.modifiedCount
      }
    });
    
    logger.logSecurityEvent('all_sessions_terminated', {
      userId: req.user._id,
      terminatedCount: result.modifiedCount,
      ipAddress: req.ip
    });
    
    res.json({
      message: `Successfully terminated ${result.modifiedCount} sessions`,
      terminatedCount: result.modifiedCount
    });
    
  } catch (error) {
    logger.error('Mass session termination error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to terminate sessions'
    });
  }
});

// @route   DELETE /api/users/account
// @desc    Delete user account
// @access  Private
router.delete('/account', [
  verifyToken,
  body('password').notEmpty().withMessage('Password is required for account deletion'),
  body('confirmText')
    .equals('DELETE MY ACCOUNT')
    .withMessage('Please type "DELETE MY ACCOUNT" to confirm')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const { password } = req.body;
    
    // Verify password
    const isMatch = await req.user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({
        error: 'Account deletion failed',
        message: 'Incorrect password'
      });
    }
    
    // Soft delete user account
    req.user.isActive = false;
    req.user.email = `deleted_${Date.now()}_${req.user.email}`;
    req.user.phone = `deleted_${Date.now()}_${req.user.phone}`;
    await req.user.save();
    
    // Terminate all sessions
    await LoginSession.updateMany(
      { userId: req.user._id, isActive: true },
      {
        $set: {
          isActive: false,
          terminationReason: 'account_deleted',
          logoutTime: new Date()
        }
      }
    );
    
    // Soft delete photos
    await Photo.updateMany(
      { userId: req.user._id },
      {
        $set: {
          isDeleted: true,
          deletedAt: new Date()
        }
      }
    );
    
    // Log account deletion
    Analytics.logEvent({
      userId: req.user._id,
      eventType: 'account_deleted',
      eventAction: 'user_deleted_account',
      eventCategory: 'user_management',
      context: {
        location: {
          ipAddress: req.ip
        }
      }
    });
    
    logger.logUserActivity(req.user._id, 'account_deleted', {
      deletedAt: new Date(),
      ipAddress: req.ip
    });
    
    res.json({
      message: 'Account deleted successfully'
    });
    
  } catch (error) {
    logger.error('Account deletion error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to delete account'
    });
  }
});

module.exports = router;