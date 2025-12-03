const express = require('express');
const { body, validationResult } = require('express-validator');
const Crop = require('../models/Crop');
const User = require('../models/User');
const Photo = require('../models/Photo');
const Analytics = require('../models/Analytics');
const { verifyToken, userRateLimit } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Validation rules
const cropValidation = [
  body('cropName')
    .trim()
    .notEmpty()
    .withMessage('Crop name is required')
    .isLength({ max: 100 })
    .withMessage('Crop name cannot exceed 100 characters'),
    
  body('cropType')
    .isIn(['Kharif', 'Rabi', 'Zaid', 'Perennial'])
    .withMessage('Invalid crop type'),
    
  body('landDetails.areaInAcres')
    .isFloat({ min: 0.1 })
    .withMessage('Area must be at least 0.1 acres'),
    
  body('cropCalendar.sowingDate')
    .isISO8601()
    .withMessage('Invalid sowing date'),
    
  body('cropCalendar.expectedHarvestDate')
    .isISO8601()
    .withMessage('Invalid expected harvest date')
];

// @route   POST /api/crops
// @desc    Create a new crop
// @access  Private
router.post('/', [
  verifyToken,
  userRateLimit(20, 15 * 60 * 1000),
  ...cropValidation
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const cropData = {
      ...req.body,
      userId: req.user._id
    };
    
    // Validate dates
    const sowingDate = new Date(cropData.cropCalendar.sowingDate);
    const harvestDate = new Date(cropData.cropCalendar.expectedHarvestDate);
    
    if (harvestDate <= sowingDate) {
      return res.status(400).json({
        error: 'Invalid dates',
        message: 'Expected harvest date must be after sowing date'
      });
    }
    
    // Calculate crop duration
    cropData.cropCalendar.cropDuration = Math.ceil(
      (harvestDate - sowingDate) / (1000 * 60 * 60 * 24)
    );
    
    const crop = new Crop(cropData);
    await crop.save();
    
    // Log crop creation
    Analytics.logEvent({
      userId: req.user._id,
      eventType: 'crop_created',
      eventAction: 'new_crop_registered',
      eventCategory: 'crop_management',
      eventData: {
        cropId: crop._id,
        cropName: crop.cropName,
        cropType: crop.cropType,
        areaInAcres: crop.landDetails.areaInAcres
      }
    });
    
    logger.logUserActivity(req.user._id, 'crop_created', {
      cropId: crop._id,
      cropName: crop.cropName
    });
    
    res.status(201).json({
      message: 'Crop created successfully',
      crop
    });
    
  } catch (error) {
    logger.error('Crop creation error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({
        error: 'Duplicate entry',
        message: 'A crop with similar details already exists'
      });
    }
    
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to create crop'
    });
  }
});

// @route   GET /api/crops
// @desc    Get user's crops
// @access  Private
router.get('/', verifyToken, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      cropType,
      cropStatus,
      sortBy = 'createdAt',
      order = 'desc',
      search
    } = req.query;
    
    // Build query
    const query = { userId: req.user._id };
    
    if (cropType) query.cropType = cropType;
    if (cropStatus) query.cropStatus = cropStatus;
    
    if (search) {
      query.$or = [
        { cropName: { $regex: search, $options: 'i' } },
        { variety: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Execute query with pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sortOrder = order === 'desc' ? -1 : 1;
    
    const crops = await Crop.find(query)
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('userId', 'fullName email');
    
    const totalCrops = await Crop.countDocuments(query);
    
    // Add calculated fields
    const cropsWithCalculations = crops.map(crop => {
      const cropObj = crop.toObject();
      cropObj.cropAgeInDays = crop.cropAgeInDays;
      cropObj.yieldEfficiency = crop.calculateYieldEfficiency();
      return cropObj;
    });
    
    res.json({
      crops: cropsWithCalculations,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalCrops / parseInt(limit)),
        totalCrops,
        hasNext: skip + crops.length < totalCrops,
        hasPrev: parseInt(page) > 1
      }
    });
    
  } catch (error) {
    logger.error('Get crops error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to retrieve crops'
    });
  }
});

// @route   GET /api/crops/:cropId
// @desc    Get single crop details
// @access  Private
router.get('/:cropId', verifyToken, async (req, res) => {
  try {
    const { cropId } = req.params;
    
    const crop = await Crop.findById(cropId)
      .populate('userId', 'fullName email phone');
    
    if (!crop) {
      return res.status(404).json({
        error: 'Crop not found',
        message: 'The requested crop does not exist'
      });
    }
    
    // Check if user owns the crop
    if (crop.userId._id.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You can only view your own crops'
      });
    }
    
    // Get related photos
    const photos = await Photo.find({
      cropId: crop._id,
      isDeleted: false
    }).select('filename originalName photoType createdAt url');
    
    // Add URLs to photos
    const photosWithUrls = photos.map(photo => ({
      ...photo.toObject(),
      url: `/api/upload/photo/${photo._id}`
    }));
    
    const cropData = {
      ...crop.toObject(),
      cropAgeInDays: crop.cropAgeInDays,
      yieldEfficiency: crop.calculateYieldEfficiency(),
      photos: photosWithUrls
    };
    
    res.json({
      crop: cropData
    });
    
  } catch (error) {
    logger.error('Get crop details error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to retrieve crop details'
    });
  }
});

// @route   PUT /api/crops/:cropId
// @desc    Update crop details
// @access  Private
router.put('/:cropId', [
  verifyToken,
  body('cropName')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Crop name cannot exceed 100 characters'),
    
  body('landDetails.areaInAcres')
    .optional()
    .isFloat({ min: 0.1 })
    .withMessage('Area must be at least 0.1 acres')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const { cropId } = req.params;
    
    const crop = await Crop.findById(cropId);
    if (!crop) {
      return res.status(404).json({
        error: 'Crop not found',
        message: 'The requested crop does not exist'
      });
    }
    
    // Check if user owns the crop
    if (crop.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You can only update your own crops'
      });
    }
    
    // Update allowed fields
    const allowedUpdates = [
      'cropName', 'variety', 'landDetails', 'cropCalendar',
      'insuranceDetails', 'monitoring', 'harvestData', 'notes'
    ];
    
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        if (field === 'landDetails' || field === 'cropCalendar' || 
            field === 'insuranceDetails' || field === 'monitoring' || 
            field === 'harvestData') {
          crop[field] = { ...crop[field].toObject(), ...req.body[field] };
        } else {
          crop[field] = req.body[field];
        }
      }
    });
    
    await crop.save();
    
    // Log crop update
    Analytics.logEvent({
      userId: req.user._id,
      eventType: 'crop_updated',
      eventAction: 'crop_details_modified',
      eventCategory: 'crop_management',
      eventData: {
        cropId: crop._id,
        fieldsUpdated: Object.keys(req.body)
      }
    });
    
    logger.logUserActivity(req.user._id, 'crop_updated', {
      cropId: crop._id,
      fieldsUpdated: Object.keys(req.body)
    });
    
    res.json({
      message: 'Crop updated successfully',
      crop
    });
    
  } catch (error) {
    logger.error('Crop update error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to update crop'
    });
  }
});

// @route   POST /api/crops/:cropId/growth-stage
// @desc    Add growth stage update
// @access  Private
router.post('/:cropId/growth-stage', [
  verifyToken,
  body('stage')
    .isIn(['Germination', 'Seedling', 'Vegetative', 'Flowering', 'Fruiting', 'Maturity'])
    .withMessage('Invalid growth stage'),
    
  body('date')
    .isISO8601()
    .withMessage('Invalid date')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const { cropId } = req.params;
    const { stage, date, healthScore, notes, photos } = req.body;
    
    const crop = await Crop.findById(cropId);
    if (!crop) {
      return res.status(404).json({
        error: 'Crop not found'
      });
    }
    
    if (crop.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        error: 'Access denied'
      });
    }
    
    const stageData = {
      stage,
      date: new Date(date),
      healthScore,
      notes,
      photos: photos || []
    };
    
    await crop.updateGrowthStage(stageData);
    
    // Log growth stage update
    Analytics.logEvent({
      userId: req.user._id,
      eventType: 'growth_stage_updated',
      eventAction: 'stage_recorded',
      eventCategory: 'crop_management',
      eventData: {
        cropId: crop._id,
        stage,
        healthScore
      }
    });
    
    res.json({
      message: 'Growth stage updated successfully',
      crop
    });
    
  } catch (error) {
    logger.error('Growth stage update error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to update growth stage'
    });
  }
});

// @route   POST /api/crops/:cropId/weather-event
// @desc    Add weather event
// @access  Private
router.post('/:cropId/weather-event', [
  verifyToken,
  body('eventType')
    .isIn(['Drought', 'Flood', 'Hailstorm', 'Cyclone', 'Unseasonal_Rain', 'Extreme_Heat', 'Frost'])
    .withMessage('Invalid weather event type'),
    
  body('severity')
    .isIn(['Low', 'Moderate', 'High', 'Severe'])
    .withMessage('Invalid severity level')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const { cropId } = req.params;
    const {
      eventType,
      date,
      severity,
      damageAssessment,
      photos
    } = req.body;
    
    const crop = await Crop.findById(cropId);
    if (!crop) {
      return res.status(404).json({
        error: 'Crop not found'
      });
    }
    
    if (crop.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        error: 'Access denied'
      });
    }
    
    const eventData = {
      eventType,
      date: new Date(date),
      severity,
      damageAssessment: damageAssessment || {},
      photos: photos || []
    };
    
    await crop.addWeatherEvent(eventData);
    
    // Log weather event
    Analytics.logEvent({
      userId: req.user._id,
      eventType: 'weather_event_added',
      eventAction: 'weather_impact_recorded',
      eventCategory: 'crop_management',
      eventData: {
        cropId: crop._id,
        eventType,
        severity,
        percentageDamage: damageAssessment?.percentageDamage
      }
    });
    
    res.json({
      message: 'Weather event added successfully',
      crop
    });
    
  } catch (error) {
    logger.error('Weather event error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to add weather event'
    });
  }
});

// @route   GET /api/crops/statistics/summary
// @desc    Get crop statistics summary
// @access  Private
router.get('/statistics/summary', verifyToken, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get crop statistics
    const [totalCrops, cropsByStatus, cropsByType, recentHarvests] = await Promise.all([
      Crop.countDocuments({ userId }),
      
      Crop.aggregate([
        { $match: { userId } },
        { $group: { _id: '$cropStatus', count: { $sum: 1 } } }
      ]),
      
      Crop.aggregate([
        { $match: { userId } },
        { $group: { _id: '$cropType', count: { $sum: 1 }, totalArea: { $sum: '$landDetails.areaInAcres' } } }
      ]),
      
      Crop.find({
        userId,
        cropStatus: 'Harvested',
        'harvestData.actualYield': { $exists: true }
      })
      .sort({ 'cropCalendar.actualHarvestDate': -1 })
      .limit(5)
      .select('cropName cropType harvestData.actualYield cropCalendar.actualHarvestDate')
    ]);
    
    // Calculate total area and average yield
    const totalArea = await Crop.aggregate([
      { $match: { userId } },
      { $group: { _id: null, totalArea: { $sum: '$landDetails.areaInAcres' } } }
    ]);
    
    const averageYield = await Crop.aggregate([
      {
        $match: {
          userId,
          'harvestData.actualYield': { $exists: true, $gt: 0 }
        }
      },
      {
        $group: {
          _id: null,
          avgYield: { $avg: '$harvestData.actualYield' },
          totalYield: { $sum: '$harvestData.actualYield' }
        }
      }
    ]);
    
    const statistics = {
      totalCrops,
      totalArea: totalArea[0]?.totalArea || 0,
      cropsByStatus: cropsByStatus.reduce((acc, item) => {
        acc[item._id] = item.count;
        return acc;
      }, {}),
      cropsByType: cropsByType.map(item => ({
        type: item._id,
        count: item.count,
        totalArea: item.totalArea
      })),
      averageYield: averageYield[0]?.avgYield || 0,
      totalYield: averageYield[0]?.totalYield || 0,
      recentHarvests
    };
    
    res.json({
      statistics
    });
    
  } catch (error) {
    logger.error('Crop statistics error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to retrieve crop statistics'
    });
  }
});

module.exports = router;