import os
from flask import Blueprint, request, jsonify, session
from werkzeug.utils import secure_filename
from ..services.risk_engine import UnifiedRiskEngine
from ..models.analysis import AnalysisModel
from ..config import Config

analysis_bp = Blueprint('analysis', __name__)
risk_engine = UnifiedRiskEngine()

@analysis_bp.route('/api/quick-demo-analyze', methods=['POST'])
def quick_demo_analyze():
    """Public analysis endpoint for interactive demo on landing page."""
    data = request.get_json() or {}
    email_text = data.get('email_text', '')
    if not email_text:
        return jsonify({'success': False, 'error': 'No email text provided'}), 400
        
    try:
        result = risk_engine.analyze_email(
            email_text=email_text,
            email_subject=data.get('email_subject', ''),
            email_from=data.get('email_from', '')
        )
        return jsonify({'success': True, 'result': result})
    except Exception:
        return jsonify({'success': False, 'error': 'An error occurred during threat analysis.'}), 500

@analysis_bp.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    """Authenticated multi-vector threat analysis endpoint supporting multipart uploads."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    email_text = ""
    email_subject = ""
    email_from = ""
    email_to = ""
    attachments = []
    images = []
    
    # Handle Multipart Form Data (Text + File Uploads)
    if request.content_type and 'multipart/form-data' in request.content_type:
        email_text = request.form.get('email_text', '')
        email_subject = request.form.get('email_subject', '')
        email_from = request.form.get('email_from', '')
        email_to = request.form.get('email_to', '')
        
        # Process uploaded files safely
        for file_key in request.files:
            file_storage = request.files[file_key]
            if file_storage.filename:
                fn = secure_filename(file_storage.filename)
                content = file_storage.read()
                file_dict = {'filename': fn, 'content': content, 'size': len(content)}
                
                # Segregate images vs documents
                ext = os.path.splitext(fn.lower())[1]
                if ext in ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff'):
                    images.append(file_dict)
                else:
                    attachments.append(file_dict)
    else:
        # JSON Payload
        data = request.get_json() or {}
        email_text = data.get('email_text', '')
        email_subject = data.get('email_subject', '')
        email_from = data.get('email_from', '')
        email_to = data.get('email_to', '')

    if not email_text and not attachments and not images:
        return jsonify({'success': False, 'error': 'Please provide email content or attachment to analyze'}), 400

    try:
        # Run Unified Risk Engine
        report = risk_engine.analyze_email(
            email_text=email_text,
            email_subject=email_subject,
            email_from=email_from,
            email_to=email_to,
            attachments=attachments,
            images=images
        )
        
        # Persist Analysis to Database
        saved_id = AnalysisModel.save_analysis(report)
        report['id'] = saved_id
        
        # Backward compatibility format for V1 dashboard scripts
        v1_compat_result = {
            'is_bullying': report['bullying_analysis']['is_bullying'],
            'confidence': report['bullying_analysis']['confidence'],
            'rule_based_matches': report['bullying_analysis']['rule_based_matches'],
            'rule_based_score': report['bullying_analysis']['rule_based_score'],
            'ml_prediction': report['bullying_analysis']['ml_prediction'],
            'ml_confidence': report['bullying_analysis']['ml_confidence'],
            'model_used': report['bullying_analysis']['model_used'],
            'combined_score': report['bullying_analysis']['combined_score']
        }
        
        return jsonify({
            'success': True,
            'report': report,
            'result': v1_compat_result  # backward-compatible with V1
        })
        
    except Exception:
        return jsonify({'success': False, 'error': 'An internal error occurred while processing the threat analysis.'}), 500

@analysis_bp.route('/api/analysis-history', methods=['GET'])
def get_analysis_history():
    """Retrieves recent analysis history records."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
    except (ValueError, TypeError):
        limit = 50
        
    risk_filter = request.args.get('risk')
    search = request.args.get('search')
    
    try:
        history = AnalysisModel.get_history(limit=limit, risk_filter=risk_filter, search=search)
        return jsonify({'success': True, 'history': history})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to retrieve analysis history records.'}), 500

@analysis_bp.route('/api/analysis/<int:analysis_id>', methods=['GET'])
def get_analysis_details(analysis_id):
    """Retrieves full details and evidence for a specific analysis record."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        record = AnalysisModel.get_by_id(analysis_id)
        if not record:
            return jsonify({'success': False, 'error': 'Analysis record not found'}), 404
        return jsonify({'success': True, 'analysis': record})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to retrieve incident telemetry.'}), 500

@analysis_bp.route('/api/system-stats', methods=['GET'])
def get_system_stats():
    """Retrieves aggregated threat intelligence statistics."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        stats = AnalysisModel.get_dashboard_stats()
        return jsonify({'success': True, 'stats': stats})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to compute telemetry statistics.'}), 500
