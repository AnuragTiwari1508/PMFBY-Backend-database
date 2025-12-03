import os
import sys
import json
import logging
from datetime import datetime
import numpy as np
from PIL import Image
import io
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
import tensorflow as tf
from werkzeug.utils import secure_filename
import requests
from threading import Thread
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('../logs/ml_server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
MODEL_PATH = os.environ.get('MODEL_PATH', './models/')
BACKEND_API_URL = os.environ.get('BACKEND_API_URL', 'http://localhost:3000/api')

# Global model variables
models = {
    'disease_detection': None,
    'pest_detection': None,
    'crop_health': None,
    'yield_prediction': None
}

# Disease and pest classes
DISEASE_CLASSES = [
    'healthy',
    'bacterial_leaf_blight',
    'brown_spot',
    'leaf_blast',
    'tungro',
    'bacterial_leaf_streak',
    'leaf_scald',
    'narrow_brown_spot'
]

PEST_CLASSES = [
    'no_pest',
    'brown_planthopper',
    'green_leafhopper',
    'rice_hispa',
    'stem_borer',
    'army_worm',
    'leaf_folder'
]

CROP_TYPES = {
    'rice': ['kharif', 'rabi'],
    'wheat': ['rabi'],
    'maize': ['kharif', 'rabi'],
    'sugarcane': ['perennial'],
    'cotton': ['kharif'],
    'soybean': ['kharif'],
    'groundnut': ['kharif', 'rabi']
}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_models():
    """Load all ML models"""
    try:
        # Load disease detection model
        try:
            models['disease_detection'] = tf.keras.models.load_model(
                os.path.join(MODEL_PATH, 'crop_disease_model.h5')
            )
            logger.info("Disease detection model loaded successfully")
        except Exception as e:
            logger.warning(f"Could not load disease detection model: {e}")
            models['disease_detection'] = None
        
        # Load pest detection model
        try:
            models['pest_detection'] = tf.keras.models.load_model(
                os.path.join(MODEL_PATH, 'pest_detection_model.h5')
            )
            logger.info("Pest detection model loaded successfully")
        except Exception as e:
            logger.warning(f"Could not load pest detection model: {e}")
            models['pest_detection'] = None
        
        # Load crop health assessment model
        try:
            models['crop_health'] = tf.keras.models.load_model(
                os.path.join(MODEL_PATH, 'crop_health_model.h5')
            )
            logger.info("Crop health model loaded successfully")
        except Exception as e:
            logger.warning(f"Could not load crop health model: {e}")
            models['crop_health'] = None
        
        # Load yield prediction model
        try:
            models['yield_prediction'] = tf.keras.models.load_model(
                os.path.join(MODEL_PATH, 'yield_prediction_model.h5')
            )
            logger.info("Yield prediction model loaded successfully")
        except Exception as e:
            logger.warning(f"Could not load yield prediction model: {e}")
            models['yield_prediction'] = None
            
    except Exception as e:
        logger.error(f"Error loading models: {e}")

def preprocess_image(image_data, target_size=(224, 224)):
    """Preprocess image for model prediction"""
    try:
        # Convert base64 to image if needed
        if isinstance(image_data, str):
            # Remove data URL prefix if present
            if 'base64,' in image_data:
                image_data = image_data.split('base64,')[1]
            image_data = base64.b64decode(image_data)
        
        # Open and process image
        img = Image.open(io.BytesIO(image_data))
        img = img.convert('RGB')
        img = img.resize(target_size)
        
        # Convert to numpy array
        img_array = np.array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = img_array.astype('float32') / 255.0
        
        return img_array
    except Exception as e:
        logger.error(f"Error preprocessing image: {e}")
        raise

def analyze_disease(image_array):
    """Analyze image for crop diseases"""
    if models['disease_detection'] is None:
        return {
            'detected': False,
            'diseases': [],
            'error': 'Disease detection model not available'
        }
    
    try:
        # Make prediction
        predictions = models['disease_detection'].predict(image_array)
        
        # Process results
        diseases = []
        for i, confidence in enumerate(predictions[0]):
            if confidence > 0.3:  # Threshold for detection
                disease_name = DISEASE_CLASSES[i]
                severity = 'Low'
                if confidence > 0.7:
                    severity = 'High'
                elif confidence > 0.5:
                    severity = 'Moderate'
                
                recommendation = get_disease_recommendation(disease_name)
                
                diseases.append({
                    'name': disease_name,
                    'confidence': float(confidence),
                    'severity': severity,
                    'recommendation': recommendation
                })
        
        # Sort by confidence
        diseases.sort(key=lambda x: x['confidence'], reverse=True)
        
        return {
            'detected': len(diseases) > 0 and diseases[0]['name'] != 'healthy',
            'diseases': diseases[:3]  # Top 3 predictions
        }
    
    except Exception as e:
        logger.error(f"Error in disease analysis: {e}")
        return {
            'detected': False,
            'diseases': [],
            'error': str(e)
        }

def analyze_pests(image_array):
    """Analyze image for pest detection"""
    if models['pest_detection'] is None:
        return {
            'detected': False,
            'pests': [],
            'error': 'Pest detection model not available'
        }
    
    try:
        # Make prediction
        predictions = models['pest_detection'].predict(image_array)
        
        # Process results
        pests = []
        for i, confidence in enumerate(predictions[0]):
            if confidence > 0.3 and PEST_CLASSES[i] != 'no_pest':
                pest_name = PEST_CLASSES[i]
                severity = 'Low'
                if confidence > 0.7:
                    severity = 'High'
                elif confidence > 0.5:
                    severity = 'Moderate'
                
                pests.append({
                    'name': pest_name,
                    'confidence': float(confidence),
                    'count': estimate_pest_count(confidence),
                    'severity': severity
                })
        
        # Sort by confidence
        pests.sort(key=lambda x: x['confidence'], reverse=True)
        
        return {
            'detected': len(pests) > 0,
            'pests': pests[:3]  # Top 3 predictions
        }
    
    except Exception as e:
        logger.error(f"Error in pest analysis: {e}")
        return {
            'detected': False,
            'pests': [],
            'error': str(e)
        }

def assess_crop_health(image_array):
    """Assess overall crop health"""
    if models['crop_health'] is None:
        # Fallback to rule-based assessment
        return fallback_health_assessment()
    
    try:
        # Make prediction
        predictions = models['crop_health'].predict(image_array)
        health_score = float(predictions[0][0]) * 100
        
        # Determine health category
        if health_score >= 90:
            health_category = 'Excellent'
        elif health_score >= 75:
            health_category = 'Good'
        elif health_score >= 60:
            health_category = 'Fair'
        elif health_score >= 40:
            health_category = 'Poor'
        else:
            health_category = 'Critical'
        
        # Generate health indicators
        indicators = generate_health_indicators(health_score)
        
        return {
            'overallHealth': health_category,
            'healthScore': health_score,
            'indicators': indicators
        }
    
    except Exception as e:
        logger.error(f"Error in health assessment: {e}")
        return fallback_health_assessment()

def fallback_health_assessment():
    """Fallback health assessment when model is not available"""
    return {
        'overallHealth': 'Fair',
        'healthScore': 65.0,
        'indicators': [
            {'parameter': 'leaf_color', 'value': 'Green', 'score': 70},
            {'parameter': 'growth_rate', 'value': 'Normal', 'score': 65},
            {'parameter': 'plant_density', 'value': 'Adequate', 'score': 60}
        ]
    }

def generate_health_indicators(health_score):
    """Generate health indicators based on score"""
    indicators = []
    
    # Leaf color indicator
    if health_score >= 80:
        indicators.append({'parameter': 'leaf_color', 'value': 'Dark Green', 'score': min(health_score + 5, 100)})
    elif health_score >= 60:
        indicators.append({'parameter': 'leaf_color', 'value': 'Green', 'score': health_score})
    else:
        indicators.append({'parameter': 'leaf_color', 'value': 'Yellowish', 'score': health_score - 10})
    
    # Growth rate indicator
    indicators.append({'parameter': 'growth_rate', 'value': 'Normal' if health_score >= 60 else 'Slow', 'score': health_score})
    
    # Plant density indicator
    indicators.append({'parameter': 'plant_density', 'value': 'Good' if health_score >= 70 else 'Adequate', 'score': health_score - 5})
    
    return indicators

def get_disease_recommendation(disease_name):
    """Get treatment recommendation for detected disease"""
    recommendations = {
        'bacterial_leaf_blight': 'Apply copper-based bactericide. Improve field drainage and avoid over-fertilization.',
        'brown_spot': 'Apply fungicide containing tricyclazole or mancozeb. Ensure balanced nutrition.',
        'leaf_blast': 'Use blast-resistant varieties. Apply fungicides like tricyclazole or carbendazim.',
        'tungro': 'Control green leafhopper vectors. Remove infected plants. Use resistant varieties.',
        'bacterial_leaf_streak': 'Apply copper-based bactericide. Avoid overhead irrigation.',
        'leaf_scald': 'Apply fungicide and ensure proper field sanitation.',
        'narrow_brown_spot': 'Apply mancozeb or propiconazole. Maintain proper plant spacing.'
    }
    return recommendations.get(disease_name, 'Consult with agricultural expert for proper treatment.')

def estimate_pest_count(confidence):
    """Estimate pest count based on confidence"""
    if confidence > 0.8:
        return 'High (>10)'
    elif confidence > 0.6:
        return 'Medium (5-10)'
    else:
        return 'Low (1-5)'

def predict_yield(crop_data):
    """Predict crop yield based on various factors"""
    if models['yield_prediction'] is None:
        return fallback_yield_prediction(crop_data)
    
    try:
        # Prepare features for yield prediction
        features = prepare_yield_features(crop_data)
        
        # Make prediction
        prediction = models['yield_prediction'].predict(features)
        predicted_yield = float(prediction[0][0])
        
        # Calculate confidence based on input data quality
        confidence = calculate_prediction_confidence(crop_data)
        
        # Generate contributing factors
        factors = analyze_yield_factors(crop_data, predicted_yield)
        
        return {
            'predictedYield': predicted_yield,
            'confidence': confidence,
            'factors': factors
        }
    
    except Exception as e:
        logger.error(f"Error in yield prediction: {e}")
        return fallback_yield_prediction(crop_data)

def fallback_yield_prediction(crop_data):
    """Fallback yield prediction when model is not available"""
    crop_type = crop_data.get('cropName', '').lower()
    area = crop_data.get('landDetails', {}).get('areaInAcres', 1)
    
    # Average yield estimates per acre (in quintals)
    average_yields = {
        'rice': 25,
        'wheat': 30,
        'maize': 35,
        'cotton': 15,
        'sugarcane': 300,
        'soybean': 12
    }
    
    base_yield = average_yields.get(crop_type, 20)
    predicted_yield = base_yield * area
    
    return {
        'predictedYield': predicted_yield,
        'confidence': 0.6,
        'factors': [
            'Historical average yield data',
            'Regional crop patterns',
            'Standard agricultural practices'
        ]
    }

def prepare_yield_features(crop_data):
    """Prepare features for yield prediction model"""
    # Extract relevant features
    features = [
        crop_data.get('landDetails', {}).get('areaInAcres', 1),
        len(crop_data.get('monitoring', {}).get('fertilizerUsed', [])),
        len(crop_data.get('monitoring', {}).get('pesticideUsed', [])),
        len(crop_data.get('monitoring', {}).get('irrigationSchedule', [])),
        len(crop_data.get('weatherEvents', [])),
        crop_data.get('aiAnalysis', {}).get('riskAssessment', {}).get('riskLevel', 2)  # Default medium risk
    ]
    
    return np.array([features])

def calculate_prediction_confidence(crop_data):
    """Calculate confidence score for yield prediction"""
    confidence = 0.5  # Base confidence
    
    # Increase confidence based on available data
    if crop_data.get('monitoring', {}).get('fertilizerUsed'):
        confidence += 0.1
    if crop_data.get('monitoring', {}).get('irrigationSchedule'):
        confidence += 0.1
    if crop_data.get('growthStages'):
        confidence += 0.15
    if crop_data.get('weatherEvents'):
        confidence += 0.1
    
    return min(confidence, 0.95)

def analyze_yield_factors(crop_data, predicted_yield):
    """Analyze factors contributing to yield prediction"""
    factors = []
    
    # Fertilizer usage
    fertilizer_count = len(crop_data.get('monitoring', {}).get('fertilizerUsed', []))
    if fertilizer_count > 3:
        factors.append('Good fertilizer management')
    elif fertilizer_count < 2:
        factors.append('Limited fertilizer usage')
    
    # Irrigation
    irrigation_count = len(crop_data.get('monitoring', {}).get('irrigationSchedule', []))
    if irrigation_count > 5:
        factors.append('Adequate irrigation')
    
    # Weather events
    weather_events = len(crop_data.get('weatherEvents', []))
    if weather_events > 2:
        factors.append('Weather stress factors')
    
    # Growth monitoring
    growth_stages = len(crop_data.get('growthStages', []))
    if growth_stages > 3:
        factors.append('Regular growth monitoring')
    
    return factors if factors else ['Standard crop management practices']

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    model_status = {}
    for model_name, model in models.items():
        model_status[model_name] = 'loaded' if model is not None else 'not_loaded'
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'models': model_status
    })

@app.route('/analyze/image', methods=['POST'])
def analyze_image():
    """Analyze image for diseases, pests, and crop health"""
    try:
        if 'image' not in request.files and 'imageData' not in request.json:
            return jsonify({
                'error': 'No image provided',
                'message': 'Please provide an image file or base64 image data'
            }), 400
        
        # Get image data
        if 'image' in request.files:
            file = request.files['image']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            if not allowed_file(file.filename):
                return jsonify({'error': 'File type not allowed'}), 400
            
            image_data = file.read()
        else:
            image_data = request.json.get('imageData')
        
        # Preprocess image
        image_array = preprocess_image(image_data)
        
        # Perform analysis
        disease_analysis = analyze_disease(image_array)
        pest_analysis = analyze_pests(image_array)
        health_assessment = assess_crop_health(image_array)
        
        # Image quality assessment
        quality_score = assess_image_quality(image_array)
        
        result = {
            'processed': True,
            'processedAt': datetime.now().isoformat(),
            'diseaseDetection': disease_analysis,
            'pestDetection': pest_analysis,
            'healthAssessment': health_assessment,
            'imageQuality': quality_score
        }
        
        logger.info(f"Image analysis completed. Diseases: {len(disease_analysis.get('diseases', []))}, Pests: {len(pest_analysis.get('pests', []))}")
        
        return jsonify({
            'success': True,
            'analysis': result
        })
    
    except Exception as e:
        logger.error(f"Error in image analysis: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Image analysis failed'
        }), 500

@app.route('/predict/yield', methods=['POST'])
def predict_crop_yield():
    """Predict crop yield based on crop data"""
    try:
        crop_data = request.json
        
        if not crop_data:
            return jsonify({
                'error': 'No crop data provided',
                'message': 'Please provide crop data for yield prediction'
            }), 400
        
        # Predict yield
        yield_prediction = predict_yield(crop_data)
        
        logger.info(f"Yield prediction completed for crop: {crop_data.get('cropName', 'Unknown')}")
        
        return jsonify({
            'success': True,
            'prediction': yield_prediction
        })
    
    except Exception as e:
        logger.error(f"Error in yield prediction: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Yield prediction failed'
        }), 500

@app.route('/assess/risk', methods=['POST'])
def assess_crop_risk():
    """Assess crop risk based on various factors"""
    try:
        crop_data = request.json
        
        if not crop_data:
            return jsonify({
                'error': 'No crop data provided'
            }), 400
        
        # Perform risk assessment
        risk_assessment = perform_risk_assessment(crop_data)
        
        logger.info(f"Risk assessment completed for crop: {crop_data.get('cropName', 'Unknown')}")
        
        return jsonify({
            'success': True,
            'assessment': risk_assessment
        })
    
    except Exception as e:
        logger.error(f"Error in risk assessment: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Risk assessment failed'
        }), 500

def assess_image_quality(image_array):
    """Assess image quality for analysis"""
    try:
        # Simple quality metrics
        img = image_array[0]  # Remove batch dimension
        
        # Calculate sharpness (variance of Laplacian)
        gray = np.mean(img, axis=2)
        laplacian_var = np.var(gray)
        sharpness = min(laplacian_var / 1000, 1.0)  # Normalize
        
        # Calculate brightness
        brightness = np.mean(img)
        
        # Calculate contrast
        contrast = np.std(img)
        
        # Overall quality score
        if sharpness > 0.8 and 0.3 < brightness < 0.8:
            quality = 'Excellent'
        elif sharpness > 0.6 and 0.2 < brightness < 0.9:
            quality = 'Good'
        elif sharpness > 0.4:
            quality = 'Fair'
        else:
            quality = 'Poor'
        
        return {
            'sharpness': float(sharpness),
            'brightness': float(brightness),
            'contrast': float(contrast),
            'overallQuality': quality
        }
    
    except Exception as e:
        logger.error(f"Error assessing image quality: {e}")
        return {
            'sharpness': 0.5,
            'brightness': 0.5,
            'contrast': 0.5,
            'overallQuality': 'Fair'
        }

def perform_risk_assessment(crop_data):
    """Perform comprehensive crop risk assessment"""
    risk_factors = []
    risk_score = 0
    
    # Weather-based risks
    weather_events = crop_data.get('weatherEvents', [])
    severe_events = [e for e in weather_events if e.get('severity') in ['High', 'Severe']]
    
    if len(severe_events) > 2:
        risk_factors.append('Multiple severe weather events')
        risk_score += 30
    elif len(severe_events) > 0:
        risk_factors.append('Weather stress detected')
        risk_score += 15
    
    # Disease and pest risks
    ai_analysis = crop_data.get('aiAnalysis', {})
    if ai_analysis.get('diseaseDetection', {}).get('detected'):
        diseases = ai_analysis['diseaseDetection'].get('diseases', [])
        severe_diseases = [d for d in diseases if d.get('severity') in ['High', 'Severe']]
        if severe_diseases:
            risk_factors.append('Severe disease detected')
            risk_score += 25
        else:
            risk_factors.append('Disease detected')
            risk_score += 10
    
    # Management risks
    monitoring = crop_data.get('monitoring', {})
    if len(monitoring.get('fertilizerUsed', [])) < 2:
        risk_factors.append('Inadequate fertilizer management')
        risk_score += 10
    
    if len(monitoring.get('irrigationSchedule', [])) < 3:
        risk_factors.append('Insufficient irrigation')
        risk_score += 15
    
    # Growth stage risks
    growth_stages = crop_data.get('growthStages', [])
    if len(growth_stages) < 3:
        risk_factors.append('Limited growth monitoring')
        risk_score += 5
    
    # Determine risk level
    if risk_score > 50:
        risk_level = 'Critical'
    elif risk_score > 30:
        risk_level = 'High'
    elif risk_score > 15:
        risk_level = 'Moderate'
    else:
        risk_level = 'Low'
    
    # Generate recommendations
    recommendations = generate_risk_recommendations(risk_factors, risk_level)
    
    return {
        'riskLevel': risk_level,
        'riskScore': risk_score,
        'riskFactors': risk_factors,
        'recommendations': recommendations,
        'assessmentDate': datetime.now().isoformat()
    }

def generate_risk_recommendations(risk_factors, risk_level):
    """Generate recommendations based on risk assessment"""
    recommendations = []
    
    if 'Multiple severe weather events' in risk_factors:
        recommendations.append('Consider crop insurance claim if damage exceeds threshold')
        recommendations.append('Implement immediate damage control measures')
    
    if 'Severe disease detected' in risk_factors:
        recommendations.append('Apply targeted fungicide/bactericide treatment immediately')
        recommendations.append('Isolate affected areas to prevent spread')
    
    if 'Inadequate fertilizer management' in risk_factors:
        recommendations.append('Conduct soil test and apply balanced fertilizers')
    
    if 'Insufficient irrigation' in risk_factors:
        recommendations.append('Increase irrigation frequency based on crop stage')
    
    if risk_level == 'Critical':
        recommendations.append('Consult agricultural extension officer immediately')
        recommendations.append('Consider emergency measures to save the crop')
    
    return recommendations if recommendations else ['Continue regular monitoring and maintenance']

if __name__ == '__main__':
    # Load models on startup
    logger.info("Starting ML server...")
    load_models()
    
    # Start Flask app
    port = int(os.environ.get('ML_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
