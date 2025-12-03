const express = require('express');
const axios = require('axios');
const { body, validationResult } = require('express-validator');
const Photo = require('../models/Photo');
const Crop = require('../models/Crop');
const Analytics = require('../models/Analytics');
const { verifyToken, userRateLimit } = require('../middleware/auth');
const logger = require('../utils/logger');
const FormData = require('form-data');
const fs = require('fs');

const router = express.Router();

// ML Server Configuration
const ML_SERVER_URL = process.env.PYTHON_ML_SERVER_URL || 'http://localhost:5000';
const ML_REQUEST_TIMEOUT = 30000; // 30 seconds

// Helper function to call ML server
const callMLServer = async (endpoint, data, method = 'POST') => {
  try {
    const config = {
      method,
      url: `${ML_SERVER_URL}${endpoint}`,
      timeout: ML_REQUEST_TIMEOUT,
      headers: {
        'Content-Type': 'application/json'
      }
    };
    
    if (method === 'POST') {
      config.data = data;
    }
    
    const response = await axios(config);
    return response.data;
  } catch (error) {
    logger.error(`ML Server request failed: ${error.message}`);
    
    if (error.code === 'ECONNREFUSED') {
      throw new Error('ML server is not available');
    }
    
    if (error.response) {
      throw new Error(error.response.data.message || 'ML server error');
    }
    
    throw error;
  }
};

// @route   POST /api/ml/analyze/photo/:photoId
// @desc    Analyze photo using ML models
// @access  Private
router.post('/analyze/photo/:photoId', [
  verifyToken,
  userRateLimit(10, 15 * 60 * 1000) // 10 analysis requests per 15 minutes
], async (req, res) => {
  try {
    const { photoId } = req.params;
    
    // Find the photo
    const photo = await Photo.findById(photoId);
    if (!photo) {
      return res.status(404).json({
        error: 'Photo not found',
        message: 'The requested photo does not exist'
      });
    }
    
    // Check if user owns the photo
    if (photo.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You can only analyze your own photos'
      });
    }
    
    // Check if already processing
    if (photo.processingStatus === 'processing') {
      return res.status(409).json({
        error: 'Analysis in progress',
        message: 'Photo is already being analyzed'
      });
    }
    
    // Update processing status
    photo.processingStatus = 'processing';
    await photo.save();
    
    try {
      // Get photo file data (you'll need to implement GridFS file retrieval)
      const photoBuffer = await getPhotoBuffer(photo.gridfsId);
      
      // Convert buffer to base64
      const base64Image = photoBuffer.toString('base64');
      
      // Call ML server for analysis
      const analysisResult = await callMLServer('/analyze/image', {
        imageData: `data:image/jpeg;base64,${base64Image}`,
        photoType: photo.photoType,
        cropId: photo.cropId
      });
      
      // Update photo with analysis results
      await photo.updateAIAnalysis(analysisResult.analysis);
      
      // Log analysis event
      Analytics.logEvent({
        userId: req.user._id,
        eventType: 'ai_analysis_completed',
        eventAction: 'photo_analyzed',
        eventCategory: 'ai_ml',
        eventData: {
          photoId: photo._id,
          photoType: photo.photoType,
          diseaseDetected: analysisResult.analysis.diseaseDetection?.detected || false,
          pestDetected: analysisResult.analysis.pestDetection?.detected || false,
          healthScore: analysisResult.analysis.healthAssessment?.healthScore
        }
      });
      
      logger.logMLOperation('photo_analysis', 'disease_detection', {
        photoId: photo._id,
        userId: req.user._id,
        success: true
      });
      
      res.json({
        message: 'Photo analysis completed successfully',
        analysis: analysisResult.analysis,
        photo: {
          id: photo._id,
          processingStatus: photo.processingStatus,
          updatedAt: photo.updatedAt
        }
      });
      
    } catch (mlError) {
      // Update photo with error status
      photo.processingStatus = 'failed';
      photo.processingError = mlError.message;
      await photo.save();
      
      logger.error(`ML analysis failed for photo ${photoId}:`, mlError);
      
      // Log failed analysis
      Analytics.logEvent({
        userId: req.user._id,
        eventType: 'ai_analysis_requested',
        eventAction: 'analysis_failed',
        eventCategory: 'ai_ml',
        status: 'failure',
        error: {
          message: mlError.message,
          severity: 'medium'
        }
      });
      
      return res.status(500).json({
        error: 'Analysis failed',
        message: mlError.message.includes('ML server') ? 
          'AI analysis service is temporarily unavailable' : 
          'Failed to analyze photo. Please try again.'
      });
    }
    
  } catch (error) {
    logger.error('Photo analysis error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to process photo analysis request'
    });
  }
});

// @route   POST /api/ml/predict/yield/:cropId
// @desc    Predict crop yield using ML models
// @access  Private
router.post('/predict/yield/:cropId', [
  verifyToken,
  userRateLimit(5, 15 * 60 * 1000) // 5 predictions per 15 minutes
], async (req, res) => {
  try {
    const { cropId } = req.params;
    
    // Find the crop
    const crop = await Crop.findById(cropId).populate('userId', 'fullName');
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
        message: 'You can only predict yield for your own crops'
      });
    }
    
    try {
      // Prepare crop data for ML model
      const cropData = {
        cropName: crop.cropName,
        cropType: crop.cropType,
        landDetails: crop.landDetails,
        monitoring: crop.monitoring,
        weatherEvents: crop.weatherEvents,
        growthStages: crop.growthStages,
        aiAnalysis: crop.aiAnalysis,
        cropCalendar: crop.cropCalendar
      };
      
      // Call ML server for yield prediction
      const predictionResult = await callMLServer('/predict/yield', cropData);
      
      // Update crop with prediction
      crop.aiAnalysis.yieldPrediction = {
        ...predictionResult.prediction,
        predictionDate: new Date()
      };
      
      await crop.save();
      
      // Log prediction event
      Analytics.logEvent({
        userId: req.user._id,
        eventType: 'yield_predicted',
        eventAction: 'ml_prediction_completed',
        eventCategory: 'ai_ml',
        eventData: {
          cropId: crop._id,
          cropName: crop.cropName,
          predictedYield: predictionResult.prediction.predictedYield,
          confidence: predictionResult.prediction.confidence
        }
      });
      
      logger.logMLOperation('yield_prediction', 'yield_model', {
        cropId: crop._id,
        userId: req.user._id,
        predictedYield: predictionResult.prediction.predictedYield
      });
      
      res.json({
        message: 'Yield prediction completed successfully',
        prediction: predictionResult.prediction,
        crop: {
          id: crop._id,
          cropName: crop.cropName,
          updatedAt: crop.updatedAt
        }
      });
      
    } catch (mlError) {
      logger.error(`ML yield prediction failed for crop ${cropId}:`, mlError);
      
      return res.status(500).json({
        error: 'Prediction failed',
        message: mlError.message.includes('ML server') ? 
          'Yield prediction service is temporarily unavailable' : 
          'Failed to predict yield. Please try again.'
      });
    }
    
  } catch (error) {
    logger.error('Yield prediction error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to process yield prediction request'
    });
  }
});

// @route   POST /api/ml/assess/risk/:cropId
// @desc    Assess crop risk using ML models
// @access  Private
router.post('/assess/risk/:cropId', [
  verifyToken,
  userRateLimit(5, 15 * 60 * 1000)
], async (req, res) => {
  try {
    const { cropId } = req.params;
    
    // Find the crop
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
        message: 'You can only assess risk for your own crops'
      });
    }
    
    try {
      // Prepare crop data for risk assessment
      const cropData = crop.toObject();
      
      // Call ML server for risk assessment
      const riskResult = await callMLServer('/assess/risk', cropData);
      
      // Update crop with risk assessment
      crop.aiAnalysis.riskAssessment = {
        ...riskResult.assessment
      };
      
      await crop.save();
      
      // Log risk assessment event
      Analytics.logEvent({
        userId: req.user._id,
        eventType: 'risk_assessed',
        eventAction: 'ml_risk_assessment_completed',
        eventCategory: 'ai_ml',
        eventData: {
          cropId: crop._id,
          cropName: crop.cropName,
          riskLevel: riskResult.assessment.riskLevel,
          riskScore: riskResult.assessment.riskScore
        }
      });
      
      logger.logMLOperation('risk_assessment', 'risk_model', {
        cropId: crop._id,
        userId: req.user._id,
        riskLevel: riskResult.assessment.riskLevel
      });
      
      res.json({
        message: 'Risk assessment completed successfully',
        assessment: riskResult.assessment,
        crop: {
          id: crop._id,
          cropName: crop.cropName,
          updatedAt: crop.updatedAt
        }
      });
      
    } catch (mlError) {
      logger.error(`ML risk assessment failed for crop ${cropId}:`, mlError);
      
      return res.status(500).json({
        error: 'Risk assessment failed',
        message: mlError.message.includes('ML server') ? 
          'Risk assessment service is temporarily unavailable' : 
          'Failed to assess risk. Please try again.'
      });
    }
    
  } catch (error) {
    logger.error('Risk assessment error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to process risk assessment request'
    });
  }
});

// @route   GET /api/ml/health
// @desc    Check ML server health status
// @access  Private
router.get('/health', verifyToken, async (req, res) => {
  try {
    const healthStatus = await callMLServer('/health', {}, 'GET');
    
    res.json({
      message: 'ML server is healthy',
      status: healthStatus
    });
    
  } catch (error) {
    logger.error('ML server health check failed:', error);
    
    res.status(503).json({
      error: 'ML server unavailable',
      message: 'AI/ML services are temporarily unavailable',
      details: error.message
    });
  }
});

// @route   GET /api/ml/models/status
// @desc    Get ML models status
// @access  Private
router.get('/models/status', verifyToken, async (req, res) => {
  try {
    const healthStatus = await callMLServer('/health', {}, 'GET');
    
    const modelStatus = {
      serverStatus: 'online',
      models: healthStatus.models || {},
      lastChecked: new Date().toISOString()
    };
    
    res.json({
      status: modelStatus
    });
    
  } catch (error) {
    logger.error('ML models status check failed:', error);
    
    res.json({
      status: {
        serverStatus: 'offline',
        models: {
          disease_detection: 'unavailable',
          pest_detection: 'unavailable',
          crop_health: 'unavailable',
          yield_prediction: 'unavailable'
        },
        lastChecked: new Date().toISOString(),
        error: error.message
      }
    });
  }
});

// Helper function to get photo buffer from GridFS
const getPhotoBuffer = async (gridfsId) => {
  // This is a placeholder - you'll need to implement GridFS file retrieval
  // The actual implementation would use GridFS to download the file
  try {
    const mongoose = require('mongoose');
    const { GridFSBucket } = require('mongodb');
    
    const bucket = new GridFSBucket(mongoose.connection.db, {
      bucketName: 'photos'
    });
    
    return new Promise((resolve, reject) => {
      const chunks = [];
      const downloadStream = bucket.openDownloadStream(gridfsId);
      
      downloadStream.on('data', (chunk) => {
        chunks.push(chunk);
      });
      
      downloadStream.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
      
      downloadStream.on('error', (error) => {
        reject(error);
      });
    });
  } catch (error) {
    logger.error('Error retrieving photo from GridFS:', error);
    throw error;
  }
};

module.exports = router;