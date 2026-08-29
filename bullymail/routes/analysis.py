import os
from flask import Blueprint, request, jsonify, session
from werkzeug.utils import secure_filename
from ..services.risk_engine import UnifiedRiskEngine
from ..models.analysis import AnalysisModel
from ..config import Config

from .auth import get_current_user
from .auth import get_current_user, require_role

from ..models.institution import InstitutionModel

analysis_bp = Blueprint('analysis', __name__)
risk_engine = UnifiedRiskEngine()

def _resolve_target_institution_id(current_user, requested_inst_id=None, strict_403=False):
    """
    Validates institution access for current user.
    Admin can access any valid institution_id (or requests specific inst_id).
    Analyst/Operator is strictly locked to their assigned user['institution_id'].
    If strict_403 is True and an explicit cross-tenant requested_inst_id is passed by a non-admin, returns 403 Forbidden.
    Otherwise, tampered parameters are safely ignored and scoped to user['institution_id'].
    """
    user_role = current_user.get('role', 'analyst')
    user_inst_id = current_user.get('institution_id') or 1
    if user_role == 'admin':
        if requested_inst_id is not None:
            try:
                target_id = int(requested_inst_id)
                inst = InstitutionModel.get_by_id(target_id)
                if not inst:
                    return None, ("Institution not found", 404)
                return target_id, None
            except (ValueError, TypeError):
                return None, ("Invalid institution ID", 400)
        return user_inst_id, None
    else:
        if strict_403 and requested_inst_id is not None:
            try:
                if int(requested_inst_id) != user_inst_id:
                    return None, ("Forbidden: Access to specified institution is denied", 403)
            except (ValueError, TypeError):
                return None, ("Invalid institution ID", 400)
        return user_inst_id, None

@analysis_bp.route('/api/quick-demo-analyze', methods=['POST'])
def quick_demo_analyze():
    """Unauthenticated quick demo endpoint for instant interactive evaluation."""
    data = request.get_json() or {}
    text = (data.get('email_text') or '').strip()
    subject = (data.get('email_subject') or '').strip()
    if not text:
        return jsonify({'success': False, 'error': 'No content provided'}), 400

    report = risk_engine.analyze_email(email_text=text, email_subject=subject)
    return jsonify({'success': True, 'report': report, 'result': report})

@analysis_bp.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    """Authenticated multi-vector threat analysis endpoint supporting multipart uploads."""
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'error': 'Unauthorized or account pending approval'}), 401
        
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
        req_inst_id = request.form.get('institution_id')
        
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
        req_inst_id = data.get('institution_id')

    if not email_text and not attachments and not images:
        return jsonify({'success': False, 'error': 'Please provide email content or attachment to analyze'}), 400

    try:
        # Resolve target institution with RBAC check
        inst_id, err_resp = _resolve_target_institution_id(user, req_inst_id)
        if err_resp:
            msg, code = err_resp
            return jsonify({'success': False, 'error': msg}), code

        # Run Unified Risk Engine
        report = risk_engine.analyze_email(
            email_text=email_text,
            email_subject=email_subject,
            email_from=email_from,
            email_to=email_to,
            attachments=attachments,
            images=images
        )
        
        # Persist Analysis to Database with tenant/user ownership
        u_id = user.get('id')
        saved_id = AnalysisModel.save_analysis(report, institution_id=inst_id, user_id=u_id)
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

@analysis_bp.route('/api/institutions/<int:inst_id>/emails', methods=['GET'])
def get_institution_emails(inst_id):
    """Retrieves emails and threat analysis history scoped strictly to target institution_id."""
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    target_id, err_resp = _resolve_target_institution_id(user, inst_id, strict_403=True)
    if err_resp:
        msg, code = err_resp
        return jsonify({'success': False, 'error': msg}), code

    try:
        limit = min(int(request.args.get('limit', 50)), 500)
    except (ValueError, TypeError):
        limit = 50

    risk_filter = request.args.get('risk')
    search = request.args.get('search')
    try:
        history = AnalysisModel.get_history(limit=limit, risk_filter=risk_filter, search=search, institution_id=target_id, role=user.get('role'))
        return jsonify({'success': True, 'institution_id': target_id, 'emails': history})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to retrieve institution email records.'}), 500

@analysis_bp.route('/api/analysis-history', methods=['GET'])
def get_analysis_history():
    """Retrieves recent analysis history records scoped to active institution & user role."""
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
    except (ValueError, TypeError):
        limit = 50
        
    risk_filter = request.args.get('risk')
    search = request.args.get('search')
    req_inst = request.args.get('institution_id')
    
    try:
        target_id, err_resp = _resolve_target_institution_id(user, req_inst)
        if err_resp:
            msg, code = err_resp
            return jsonify({'success': False, 'error': msg}), code

        history = AnalysisModel.get_history(limit=limit, risk_filter=risk_filter, search=search, institution_id=target_id, user_id=user.get('id'), role=user.get('role'))
        return jsonify({'success': True, 'history': history})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to retrieve analysis history records.'}), 500

@analysis_bp.route('/api/analysis/<int:analysis_id>', methods=['GET'])
def get_analysis_details(analysis_id):
    """Retrieves full details and evidence for a specific analysis record (Tenant Isolation Enforced)."""
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        req_inst = request.args.get('institution_id')
        target_id, err_resp = _resolve_target_institution_id(user, req_inst)
        if err_resp:
            msg, code = err_resp
            return jsonify({'success': False, 'error': msg}), code

        record = AnalysisModel.get_by_id(analysis_id, institution_id=target_id, user_id=user.get('id'), role=user.get('role'))
        if not record:
            return jsonify({'success': False, 'error': 'Analysis record not found'}), 404

        req_mb = request.args.get('mailbox_id')
        if req_mb:
            try:
                req_mb_id = int(req_mb)
                rec_mb_id = record.get('email_config_id')
                if rec_mb_id and int(rec_mb_id) != req_mb_id:
                    return jsonify({'success': False, 'error': 'Analysis record not found for specified mailbox'}), 404
            except (ValueError, TypeError):
                pass

        return jsonify({'success': True, 'analysis': record})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to retrieve incident telemetry.'}), 500

@analysis_bp.route('/api/system-stats', methods=['GET'])
def get_system_stats():
    """Retrieves aggregated threat intelligence statistics scoped to active institution & user role."""
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        req_inst = request.args.get('institution_id')
        target_id, err_resp = _resolve_target_institution_id(user, req_inst)
        if err_resp:
            msg, code = err_resp
            return jsonify({'success': False, 'error': msg}), code

        stats = AnalysisModel.get_dashboard_stats(institution_id=target_id, user_id=user.get('id'), role=user.get('role'))
        return jsonify({'success': True, 'stats': stats})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to compute telemetry statistics.'}), 500
