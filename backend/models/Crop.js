const mongoose = require('mongoose');

const CropSchema = new mongoose.Schema({
  // User Reference
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User ID is required']
  },
  
  // Crop Basic Information
  cropName: {
    type: String,
    required: [true, 'Crop name is required'],
    trim: true
  },
  
  cropType: {
    type: String,
    enum: ['Kharif', 'Rabi', 'Zaid', 'Perennial'],
    required: [true, 'Crop type is required']
  },
  
  variety: {
    type: String,
    required: false,
    trim: true
  },
  
  // Land and Location Details
  landDetails: {
    surveyNumber: { type: String, required: false },
    subDivisionNumber: { type: String, required: false },
    areaInAcres: {
      type: Number,
      required: [true, 'Area in acres is required'],
      min: [0.1, 'Area must be at least 0.1 acres']
    },
    coordinates: {
      latitude: { type: Number, required: false },
      longitude: { type: Number, required: false }
    },
    soilType: {
      type: String,
      enum: ['Clay', 'Sandy', 'Loamy', 'Silty', 'Other'],
      required: false
    },
    irrigationType: {
      type: String,
      enum: ['Irrigated', 'Rain-fed', 'Mixed'],
      required: false
    }
  },
  
  // Crop Calendar
  cropCalendar: {
    sowingDate: {
      type: Date,
      required: [true, 'Sowing date is required']
    },
    expectedHarvestDate: {
      type: Date,
      required: [true, 'Expected harvest date is required']
    },
    actualHarvestDate: {
      type: Date,
      required: false
    },
    cropDuration: {
      type: Number, // in days
      required: false
    }
  },
  
  // Insurance Details
  insuranceDetails: {
    policyNumber: {
      type: String,
      required: false,
      unique: true,
      sparse: true
    },
    premiumPaid: {
      type: Number,
      required: false,
      min: 0
    },
    sumInsured: {
      type: Number,
      required: false,
      min: 0
    },
    insuranceCompany: {
      type: String,
      required: false
    },
    policyStartDate: {
      type: Date,
      required: false
    },
    policyEndDate: {
      type: Date,
      required: false
    },
    isActive: {
      type: Boolean,
      default: false
    }
  },
  
  // Crop Monitoring Data
  monitoring: {
    plantingDensity: { type: Number, required: false }, // plants per acre
    seedQuantity: { type: Number, required: false }, // in kg
    fertilizerUsed: [{
      type: { type: String, required: true },
      quantity: { type: Number, required: true },
      applicationDate: { type: Date, required: true },
      cost: { type: Number, required: false }
    }],
    pesticideUsed: [{
      type: { type: String, required: true },
      quantity: { type: Number, required: true },
      applicationDate: { type: Date, required: true },
      cost: { type: Number, required: false }
    }],
    irrigationSchedule: [{
      date: { type: Date, required: true },
      durationHours: { type: Number, required: true },
      method: { type: String, required: false }
    }]
  },
  
  // Crop Health and Growth Tracking
  growthStages: [{
    stage: {
      type: String,
      enum: ['Germination', 'Seedling', 'Vegetative', 'Flowering', 'Fruiting', 'Maturity'],
      required: true
    },
    date: {
      type: Date,
      required: true
    },
    healthScore: {
      type: Number,
      min: 1,
      max: 10,
      required: false
    },
    notes: {
      type: String,
      required: false
    },
    photos: [{
      url: String,
      description: String,
      uploadDate: { type: Date, default: Date.now }
    }]
  }],
  
  // Weather Impact Tracking
  weatherEvents: [{
    eventType: {
      type: String,
      enum: ['Drought', 'Flood', 'Hailstorm', 'Cyclone', 'Unseasonal_Rain', 'Extreme_Heat', 'Frost'],
      required: true
    },
    date: {
      type: Date,
      required: true
    },
    severity: {
      type: String,
      enum: ['Low', 'Moderate', 'High', 'Severe'],
      required: true
    },
    damageAssessment: {
      percentageDamage: {
        type: Number,
        min: 0,
        max: 100,
        required: false
      },
      estimatedLoss: {
        type: Number,
        min: 0,
        required: false
      },
      description: {
        type: String,
        required: false
      }
    },
    photos: [{
      url: String,
      description: String,
      uploadDate: { type: Date, default: Date.now }
    }]
  }],
  
  // Harvest and Yield Data
  harvestData: {
    actualYield: {
      type: Number, // in quintals
      required: false,
      min: 0
    },
    expectedYield: {
      type: Number, // in quintals
      required: false,
      min: 0
    },
    qualityGrade: {
      type: String,
      enum: ['A', 'B', 'C', 'D', 'Rejected'],
      required: false
    },
    marketPrice: {
      type: Number, // per quintal
      required: false,
      min: 0
    },
    totalIncome: {
      type: Number,
      required: false,
      min: 0
    },
    totalCost: {
      type: Number,
      required: false,
      min: 0
    },
    profit: {
      type: Number,
      required: false
    }
  },
  
  // ML/AI Analysis Results
  aiAnalysis: {
    diseaseDetection: [{
      diseaseName: String,
      confidence: Number,
      detectedDate: { type: Date, default: Date.now },
      treatmentRecommendation: String,
      severity: String
    }],
    yieldPrediction: {
      predictedYield: Number,
      confidence: Number,
      predictionDate: { type: Date, default: Date.now },
      factors: [String] // Contributing factors
    },
    riskAssessment: {
      riskLevel: {
        type: String,
        enum: ['Low', 'Moderate', 'High', 'Critical']
      },
      riskFactors: [String],
      recommendations: [String],
      assessmentDate: { type: Date, default: Date.now }
    }
  },
  
  // Status and Flags
  cropStatus: {
    type: String,
    enum: ['Planned', 'Sown', 'Growing', 'Harvested', 'Damaged', 'Failed'],
    default: 'Planned'
  },
  
  isClaimFiled: {
    type: Boolean,
    default: false
  },
  
  claimStatus: {
    type: String,
    enum: ['None', 'Filed', 'Under_Review', 'Approved', 'Rejected', 'Settled'],
    default: 'None'
  },
  
  notes: {
    type: String,
    required: false
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for better query performance
CropSchema.index({ userId: 1 });
CropSchema.index({ cropName: 1, cropType: 1 });
CropSchema.index({ 'cropCalendar.sowingDate': 1 });
CropSchema.index({ 'insuranceDetails.policyNumber': 1 });
CropSchema.index({ cropStatus: 1 });
CropSchema.index({ createdAt: -1 });

// Virtual for crop age in days
CropSchema.virtual('cropAgeInDays').get(function() {
  if (this.cropCalendar.sowingDate) {
    const today = new Date();
    const sowingDate = new Date(this.cropCalendar.sowingDate);
    const diffTime = Math.abs(today - sowingDate);
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }
  return 0;
});

// Virtual for profit calculation
CropSchema.virtual('calculatedProfit').get(function() {
  if (this.harvestData.totalIncome && this.harvestData.totalCost) {
    return this.harvestData.totalIncome - this.harvestData.totalCost;
  }
  return null;
});

// Method to calculate yield efficiency
CropSchema.methods.calculateYieldEfficiency = function() {
  if (this.harvestData.actualYield && this.harvestData.expectedYield) {
    return (this.harvestData.actualYield / this.harvestData.expectedYield) * 100;
  }
  return null;
};

// Method to add weather event
CropSchema.methods.addWeatherEvent = function(eventData) {
  this.weatherEvents.push(eventData);
  
  // Auto-update crop status based on severe weather events
  if (eventData.severity === 'Severe' && eventData.damageAssessment?.percentageDamage > 50) {
    this.cropStatus = 'Damaged';
  }
  
  return this.save();
};

// Method to update growth stage
CropSchema.methods.updateGrowthStage = function(stageData) {
  this.growthStages.push(stageData);
  return this.save();
};

// Static method to get crops by season
CropSchema.statics.findByCurrentSeason = function() {
  const currentDate = new Date();
  const currentMonth = currentDate.getMonth() + 1;
  
  let cropType;
  if (currentMonth >= 6 && currentMonth <= 11) {
    cropType = 'Kharif';
  } else if (currentMonth >= 11 || currentMonth <= 4) {
    cropType = 'Rabi';
  } else {
    cropType = 'Zaid';
  }
  
  return this.find({ cropType, cropStatus: { $in: ['Sown', 'Growing'] } });
};

module.exports = mongoose.model('Crop', CropSchema);