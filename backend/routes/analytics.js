const express = require('express');
const Analytics = require('../models/Analytics');
const User = require('../models/User');
const Crop = require('../models/Crop');
const Photo = require('../models/Photo');
const { verifyToken, requireRole } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// @route   GET /api/analytics/user/activity
// @desc    Get user activity analytics
// @access  Private
router.get('/user/activity', verifyToken, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const userId = req.user._id;
    
    const activity = await Analytics.getUserActivitySummary(userId, parseInt(days));
    
    res.json({
      activity,
      period: `${days} days`
    });
    
  } catch (error) {
    logger.error('User activity analytics error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to retrieve activity analytics'
    });
  }
});

// @route   GET /api/analytics/app/usage
// @desc    Get app usage statistics
// @access  Private (Admin only)
router.get('/app/usage', [verifyToken, requireRole(['admin'])], async (req, res) => {
  try {
    const { days = 7 } = req.query;
    
    const usage = await Analytics.getAppUsageStats(parseInt(days));
    
    res.json({
      usage,
      period: `${days} days`
    });
    
  } catch (error) {
    logger.error('App usage analytics error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to retrieve app usage analytics'
    });
  }
});

// @route   POST /api/analytics/event
// @desc    Log custom analytics event
// @access  Private
router.post('/event', verifyToken, async (req, res) => {
  try {
    const {
      eventType,
      eventAction,
      eventCategory,
      eventData,
      context
    } = req.body;
    
    if (!eventType || !eventAction || !eventCategory) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'eventType, eventAction, and eventCategory are required'
      });
    }
    
    const analyticsEvent = {
      userId: req.user._id,
      sessionId: req.session?.sessionId,
      eventType,
      eventAction,
      eventCategory,
      eventData: eventData || {},
      context: {
        ...context,
        location: {
          ipAddress: req.ip,
          ...context?.location
        }
      },
      metadata: {
        userAgent: req.get('User-Agent'),
        source: 'mobile_app'
      }
    };
    
    await Analytics.logEvent(analyticsEvent);
    
    res.json({
      message: 'Event logged successfully'
    });
    
  } catch (error) {
    logger.error('Analytics event logging error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to log analytics event'
    });
  }
});

module.exports = router;