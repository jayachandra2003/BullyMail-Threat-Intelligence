import os
import json
from flask import Blueprint, request, jsonify, session
from ..services.bullying_detector import BullyingDetector
from ..config import Config
from ..database.connection import fetch_all, execute_query

models_bp = Blueprint('models', __name__)
detector = BullyingDetector()

@models_bp.route('/api/model-status', methods=['GET'])
def get_model_status():
    """Retrieves current model status, list of serialized artifacts, and training history."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        model_files = []
        if os.path.exists(Config.MODEL_PATH):
            model_files = [f for f in os.listdir(Config.MODEL_PATH) if f.endswith('.joblib')]
            
        history = fetch_all("SELECT * FROM model_history ORDER BY created_at DESC LIMIT 10")
        
        # Parse confusion matrix JSON safely
        for h in history:
            if isinstance(h.get('confusion_matrix'), str):
                try:
                    h['confusion_matrix'] = json.loads(h['confusion_matrix'])
                except Exception:
                    h['confusion_matrix'] = []

        return jsonify({
            'success': True,
            'model_loaded': detector.model is not None and detector.vectorizer is not None,
            'model_type': detector.model_type,
            'saved_models': model_files,
            'latest_model': 'latest_model.joblib' if 'latest_model.joblib' in model_files else None,
            'training_history': history
        })
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to retrieve model registry status.'}), 500

@models_bp.route('/api/train-model', methods=['POST'])
def train_model():
    """Trains a new cyberbullying model on generated or uploaded data with proper evaluation metrics."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    data = request.get_json() or {}
    model_type = data.get('model_type', 'logistic')
    try:
        training_samples = min(max(int(data.get('training_samples', 2000)), 100), 50000)
    except (ValueError, TypeError):
        training_samples = 2000
        
    try:
        # Generate training dataset with deduplication
        from ..routes.datasets import generate_synthetic_samples
        emails, labels, telemetry = generate_synthetic_samples(training_samples)
        
        # Train model with proper train/test evaluation and atomic saving
        metrics = detector.train_model(
            emails=emails,
            labels=labels,
            model_type=model_type,
            test_size=0.25,
            is_synthetic=True
        )
        
        # Save metrics to DB
        execute_query('''
            INSERT INTO model_history (
                model_type, precision_score, recall_score, f1_score, accuracy,
                confusion_matrix, training_samples, test_samples, evaluation_type
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            metrics['model_type'],
            metrics['precision'],
            metrics['recall'],
            metrics['f1_score'],
            metrics['accuracy'],
            json.dumps(metrics['confusion_matrix']),
            metrics['training_samples'],
            metrics['test_samples'],
            metrics['evaluation_type']
        ))
        
        return jsonify({
            'success': True,
            'results': metrics,
            'dataset_telemetry': telemetry
        })
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to complete model training pipeline.'}), 500

@models_bp.route('/api/load-model', methods=['POST'])
def load_model():
    """Atomically loads a specific model and its paired vectorizer from saved_models directory."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    data = request.get_json() or {}
    model_name = data.get('model_type', 'latest')
    
    try:
        if not os.path.exists(Config.MODEL_PATH):
            return jsonify({'success': False, 'error': 'Model repository directory does not exist.'}), 404
            
        if model_name == 'latest':
            success = detector.load_latest_model()
            if success:
                return jsonify({'success': True, 'message': f"Latest model '{detector.model_type}' and vectorizer loaded successfully."})
            return jsonify({'success': False, 'error': 'Latest model artifact pair not found or incompatible.'}), 404
        else:
            # Find candidate model files matching prefix/name
            all_files = os.listdir(Config.MODEL_PATH)
            model_candidates = [
                f for f in all_files 
                if f.lower().startswith(model_name.lower()) and f.endswith('.joblib') 
                and not f.startswith('vectorizer') and not f.startswith('latest')
            ]
            
            if not model_candidates:
                return jsonify({'success': False, 'error': f"Model artifact '{model_name}' not found."}), 404
                
            target_model_file = sorted(model_candidates)[-1]
            
            # Extract timestamp from target model file (e.g. Logistic_Regression_20260811_233234.joblib -> 20260811_233234)
            parts = target_model_file.rsplit('.', 1)[0].split('_')
            if len(parts) >= 2:
                ts = "_".join(parts[-2:])
                target_vec_file = f"vectorizer_{ts}.joblib"
            else:
                target_vec_file = None
                
            if not target_vec_file or not os.path.exists(os.path.join(Config.MODEL_PATH, target_vec_file)):
                return jsonify({
                    'success': False, 
                    'error': f"Paired vectorizer for '{target_model_file}' is missing. Atomic load aborted."
                }), 400
                
            # Perform atomic load with dimension validation
            detector.load_model_pair(
                os.path.join(Config.MODEL_PATH, target_model_file),
                os.path.join(Config.MODEL_PATH, target_vec_file)
            )
            return jsonify({
                'success': True, 
                'message': f"Model '{detector.model_type}' and paired vectorizer loaded successfully."
            })
            
    except ValueError as ve:
        return jsonify({'success': False, 'error': f"Incompatible artifact pair: {str(ve)}"}), 400
    except FileNotFoundError as fe:
        return jsonify({'success': False, 'error': str(fe)}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to load model artifact pair: {str(e)}"}), 500
