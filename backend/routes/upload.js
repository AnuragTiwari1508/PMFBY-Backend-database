const express = require('express');
const multer = require('multer');
const { GridFSBucket } = require('mongodb');
const mongoose = require('mongoose');
const sharp = require('sharp');
const { body, validationResult } = require('express-validator');
const Photo = require('../models/Photo');
const Analytics = require('../models/Analytics');
const { verifyToken, userRateLimit } = require('../middleware/auth');
const logger = require('../utils/logger');
const path = require('path');
const fs = require('fs');

const router = express.Router();

// Initialize GridFS
let gfsBucket;
mongoose.connection.once('open', () => {
  gfsBucket = new GridFSBucket(mongoose.connection.db, {
    bucketName: 'photos'
  });
  logger.info('GridFS bucket initialized');
});

// Configure multer for memory storage
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  // Check file type
  if (!file.mimetype.startsWith('image/')) {
    return cb(new Error('Only image files are allowed'), false);
  }
  
  // Check allowed image types
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
  if (!allowedTypes.includes(file.mimetype)) {
    return cb(new Error('File type not supported. Please upload JPEG, PNG, or WebP images'), false);
  }
  
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB default
    files: 5 // Maximum 5 files per request
  }
});

// Helper function to extract EXIF data
const extractImageMetadata = async (buffer) => {
  try {
    const image = sharp(buffer);
    const metadata = await image.metadata();
    
    return {
      width: metadata.width,
      height: metadata.height,
      format: metadata.format,
      size: metadata.size,
      density: metadata.density,
      channels: metadata.channels,
      depth: metadata.depth,
      space: metadata.space,
      exif: metadata.exif ? await parseExifData(metadata.exif) : null
    };
  } catch (error) {
    logger.error('Error extracting image metadata:', error);
    return null;
  }
};

// Helper function to parse EXIF data
const parseExifData = async (exifBuffer) => {
  try {
    // You might want to use a proper EXIF library like 'exif-parser' or 'exifr'
    // For now, returning basic structure
    return {
      make: null,
      model: null,
      software: null,
      dateTime: null,
      gps: null,
      orientation: null
    };
  } catch (error) {
    logger.error('Error parsing EXIF data:', error);
    return null;
  }
};

// Helper function to upload to GridFS
const uploadToGridFS = (buffer, filename, metadata) => {
  return new Promise((resolve, reject) => {
    const uploadStream = gfsBucket.openUploadStream(filename, {
      metadata: metadata
    });
    
    uploadStream.on('error', (error) => {
      logger.error('GridFS upload error:', error);
      reject(error);
    });
    
    uploadStream.on('finish', (file) => {
      logger.info('File uploaded to GridFS:', file._id);
      resolve(file._id);
    });
    
    uploadStream.end(buffer);
  });
};

// Helper function to process and optimize image
const processImage = async (buffer, quality = 80) => {
  try {
    const processedBuffer = await sharp(buffer)
      .jpeg({ quality, progressive: true })
      .resize({ width: 1920, height: 1920, fit: 'inside', withoutEnlargement: true })
      .toBuffer();
    
    return processedBuffer;
  } catch (error) {
    logger.error('Error processing image:', error);
    throw error;
  }
};

// @route   POST /api/upload/photo
// @desc    Upload single photo
// @access  Private
router.post('/photo', [
  verifyToken,
  userRateLimit(20, 15 * 60 * 1000), // 20 uploads per 15 minutes
  upload.single('photo')
], async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: 'Upload failed',
        message: 'No file uploaded'
      });
    }
    
    const {
      photoType = 'other',
      description = '',
      tags = [],
      cropId,
      location
    } = req.body;
    
    // Validate photo type
    const allowedPhotoTypes = [
      'profile_photo', 'crop_field', 'crop_damage', 'disease_symptom',
      'pest_damage', 'growth_stage', 'harvest', 'weather_damage',
      'soil_condition', 'equipment', 'document', 'other'
    ];
    
    if (!allowedPhotoTypes.includes(photoType)) {
      return res.status(400).json({
        error: 'Invalid photo type',
        message: 'Please select a valid photo type'
      });
    }
    
    // Extract image metadata
    const imageMetadata = await extractImageMetadata(req.file.buffer);
    
    // Process and optimize image
    const processedBuffer = await processImage(req.file.buffer);
    
    // Generate unique filename
    const fileExtension = path.extname(req.file.originalname) || '.jpg';
    const uniqueFilename = `${req.user._id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}${fileExtension}`;
    
    // Upload to GridFS
    const gridfsId = await uploadToGridFS(processedBuffer, uniqueFilename, {
      userId: req.user._id,
      photoType,
      uploadDate: new Date(),
      originalName: req.file.originalname,
      processedSize: processedBuffer.length,
      originalSize: req.file.size
    });
    
    // Parse location data if provided
    let locationData = {};
    if (location) {
      try {
        const parsedLocation = typeof location === 'string' ? JSON.parse(location) : location;
        locationData = {
          coordinates: {
            latitude: parsedLocation.latitude,
            longitude: parsedLocation.longitude
          },
          address: parsedLocation.address,
          gpsAccuracy: parsedLocation.accuracy
        };
      } catch (error) {
        logger.error('Error parsing location data:', error);
      }
    }
    
    // Create photo document
    const photoData = {
      userId: req.user._id,
      cropId: cropId || null,
      filename: uniqueFilename,
      originalName: req.file.originalname,
      mimeType: 'image/jpeg', // Always JPEG after processing
      fileSize: processedBuffer.length,
      storageType: 'gridfs',
      gridfsId,
      photoType,
      description,
      tags: Array.isArray(tags) ? tags : tags.split(',').map(tag => tag.trim()),
      location: locationData,
      imageMetadata,
      processingStatus: 'pending'
    };
    
    const photo = new Photo(photoData);
    await photo.save();
    
    // Log upload event
    Analytics.logEvent({
      userId: req.user._id,
      eventType: 'photo_uploaded',
      eventAction: 'upload_success',
      eventCategory: 'photo_management',
      eventData: {
        photoId: photo._id,
        photoType,
        fileSize: processedBuffer.length,
        hasCropId: !!cropId,
        hasLocation: !!location
      },
      context: {
        device: {
          type: req.session?.deviceInfo?.deviceType
        }
      }
    });
    
    logger.logUserActivity(req.user._id, 'photo_uploaded', {
      photoId: photo._id,
      photoType,
      filename: uniqueFilename
    });
    
    // Generate photo URL for response
    const photoUrl = `/api/upload/photo/${photo._id}`;
    
    res.status(201).json({
      message: 'Photo uploaded successfully',
      photo: {
        id: photo._id,
        filename: photo.filename,
        originalName: photo.originalName,
        photoType: photo.photoType,
        description: photo.description,
        tags: photo.tags,
        fileSize: photo.fileSize,
        url: photoUrl,
        uploadDate: photo.createdAt,
        processingStatus: photo.processingStatus
      }
    });
    
  } catch (error) {
    logger.error('Photo upload error:', error);
    
    // Log failed upload
    Analytics.logEvent({
      userId: req.user?._id,
      eventType: 'photo_uploaded',
      eventAction: 'upload_failed',
      eventCategory: 'photo_management',
      status: 'failure',
      error: {
        message: error.message,
        severity: 'medium'
      }
    });
    
    if (error.message.includes('File too large')) {
      return res.status(413).json({
        error: 'File too large',
        message: `File size exceeds the limit of ${process.env.MAX_FILE_SIZE || '10MB'}`
      });
    }
    
    if (error.message.includes('Only image files') || error.message.includes('File type not supported')) {
      return res.status(400).json({
        error: 'Invalid file type',
        message: error.message
      });
    }
    
    res.status(500).json({
      error: 'Upload failed',
      message: 'Failed to upload photo. Please try again.'
    });
  }
});

// @route   POST /api/upload/photos
// @desc    Upload multiple photos
// @access  Private
router.post('/photos', [
  verifyToken,
  userRateLimit(10, 15 * 60 * 1000), // 10 batch uploads per 15 minutes
  upload.array('photos', 5)
], async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        error: 'Upload failed',
        message: 'No files uploaded'
      });
    }
    
    const uploadResults = [];
    const uploadErrors = [];
    
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];
      
      try {
        // Process each file similar to single upload
        const imageMetadata = await extractImageMetadata(file.buffer);
        const processedBuffer = await processImage(file.buffer);
        
        const fileExtension = path.extname(file.originalname) || '.jpg';
        const uniqueFilename = `${req.user._id}_${Date.now()}_${i}_${Math.random().toString(36).substr(2, 9)}${fileExtension}`;
        
        const gridfsId = await uploadToGridFS(processedBuffer, uniqueFilename, {
          userId: req.user._id,
          uploadDate: new Date(),
          originalName: file.originalname,
          batchUpload: true,
          batchIndex: i
        });
        
        const photoData = {
          userId: req.user._id,
          filename: uniqueFilename,
          originalName: file.originalname,
          mimeType: 'image/jpeg',
          fileSize: processedBuffer.length,
          storageType: 'gridfs',
          gridfsId,
          photoType: req.body.photoType || 'other',
          description: req.body.description || '',
          imageMetadata,
          processingStatus: 'pending'
        };
        
        const photo = new Photo(photoData);
        await photo.save();
        
        uploadResults.push({
          id: photo._id,
          filename: photo.filename,
          originalName: photo.originalName,
          url: `/api/upload/photo/${photo._id}`,
          status: 'success'
        });
        
      } catch (error) {
        logger.error(`Error uploading file ${i}:`, error);
        uploadErrors.push({
          filename: file.originalname,
          error: error.message,
          status: 'failed'
        });
      }
    }
    
    // Log batch upload event
    Analytics.logEvent({
      userId: req.user._id,
      eventType: 'photo_uploaded',
      eventAction: 'batch_upload',
      eventCategory: 'photo_management',
      eventData: {
        totalFiles: req.files.length,
        successCount: uploadResults.length,
        errorCount: uploadErrors.length
      }
    });
    
    res.status(201).json({
      message: `Batch upload completed. ${uploadResults.length} successful, ${uploadErrors.length} failed`,
      results: uploadResults,
      errors: uploadErrors
    });
    
  } catch (error) {
    logger.error('Batch upload error:', error);
    res.status(500).json({
      error: 'Batch upload failed',
      message: 'Failed to upload photos. Please try again.'
    });
  }
});

// @route   GET /api/upload/photo/:photoId
// @desc    Get photo by ID
// @access  Public (with optional auth)
router.get('/photo/:photoId', async (req, res) => {
  try {
    const { photoId } = req.params;
    
    // Find photo
    const photo = await Photo.findById(photoId);
    if (!photo || photo.isDeleted) {
      return res.status(404).json({
        error: 'Photo not found',
        message: 'The requested photo does not exist'
      });
    }
    
    // Check if photo is public or user owns it
    const token = req.header('Authorization')?.replace('Bearer ', '');
    let hasAccess = photo.isPublic;
    
    if (token && !hasAccess) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (user) {
          hasAccess = photo.userId.toString() === user._id.toString() ||
                     photo.sharedWith.some(share => share.userId.toString() === user._id.toString());
        }
      } catch (error) {
        // Token invalid, continue with public access check
      }
    }
    
    if (!hasAccess) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to view this photo'
      });
    }
    
    // Get file from GridFS
    const downloadStream = gfsBucket.openDownloadStream(photo.gridfsId);
    
    downloadStream.on('error', (error) => {
      logger.error('GridFS download error:', error);
      res.status(404).json({
        error: 'File not found',
        message: 'Photo file not found in storage'
      });
    });
    
    // Set response headers
    res.set({
      'Content-Type': photo.mimeType,
      'Content-Disposition': `inline; filename="${photo.originalName}"`,
      'Cache-Control': 'public, max-age=31536000', // 1 year cache
      'ETag': photo._id.toString()
    });
    
    // Increment view count
    photo.incrementView().catch(err => logger.error('Error incrementing view count:', err));
    
    // Pipe the file to response
    downloadStream.pipe(res);
    
  } catch (error) {
    logger.error('Photo retrieval error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to retrieve photo'
    });
  }
});

// @route   GET /api/upload/photos/user/:userId
// @desc    Get user's photos
// @access  Private
router.get('/photos/user/:userId', verifyToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20, photoType, sortBy = 'createdAt', order = 'desc' } = req.query;
    
    // Check if user can access these photos
    if (userId !== req.user._id.toString()) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You can only view your own photos'
      });
    }
    
    // Build query
    const query = {
      userId: req.user._id,
      isDeleted: false
    };
    
    if (photoType) {
      query.photoType = photoType;
    }
    
    // Execute query with pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sortOrder = order === 'desc' ? -1 : 1;
    
    const photos = await Photo.find(query)
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('cropId', 'cropName cropType')
      .select('-gridfsId -processingError');
    
    const totalPhotos = await Photo.countDocuments(query);
    
    // Add URLs to photos
    const photosWithUrls = photos.map(photo => ({
      ...photo.toObject(),
      url: `/api/upload/photo/${photo._id}`
    }));
    
    res.json({
      photos: photosWithUrls,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalPhotos / parseInt(limit)),
        totalPhotos,
        hasNext: skip + photos.length < totalPhotos,
        hasPrev: parseInt(page) > 1
      }
    });
    
  } catch (error) {
    logger.error('Get user photos error:', error);
    res.status(500).json({
      error: 'Server error',
      message: 'Failed to retrieve photos'
    });
  }
});

module.exports = router;