import io
from flask import Blueprint, request, jsonify, session, send_file, Response
from ..services.report_generator import ReportGenerator
from ..models.analysis import AnalysisModel

from .auth import get_current_user

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/api/reports/download-csv', methods=['GET'])
def download_csv():
    """Generates and downloads a CSV export of analysis records (Tenant Scoped)."""
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        req_inst = request.args.get('institution_id')
        user_role = user.get('role', 'analyst')
        inst_id = int(req_inst) if (user_role == 'admin' and req_inst) else (user.get('institution_id') or 1)

        analyses = AnalysisModel.get_history(limit=500, institution_id=inst_id, user_id=user.get('id'))
        csv_bytes = ReportGenerator.generate_csv_report(analyses)
        
        return Response(
            csv_bytes,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=bullymail_threat_report.csv'}
        )
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to generate CSV export.'}), 500

@reports_bp.route('/api/reports/view/<int:analysis_id>', methods=['GET'])
def view_html_report(analysis_id):
    """Renders a standalone printable HTML threat report (IDOR Defense & Tenant Scoped)."""
    user = get_current_user()
    if not user:
        return "Unauthorized", 401
        
    try:
        req_inst = request.args.get('institution_id')
        user_role = user.get('role', 'analyst')
        inst_id = int(req_inst) if (user_role == 'admin' and req_inst) else (user.get('institution_id') or 1)

        record = AnalysisModel.get_by_id(analysis_id, institution_id=inst_id, role=user_role)
        if not record:
            return "Report not found or access denied", 404
            
        html_bytes = ReportGenerator.generate_html_report(record)
        return Response(html_bytes, mimetype='text/html')
    except Exception:
        return "An error occurred while generating the security report.", 500

@reports_bp.route('/api/reports/download/<int:analysis_id>', methods=['GET'])
def download_report(analysis_id):
    """Downloads the standalone HTML security audit report (IDOR Defense & Tenant Scoped)."""
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        req_inst = request.args.get('institution_id')
        user_role = user.get('role', 'analyst')
        inst_id = int(req_inst) if (user_role == 'admin' and req_inst) else (user.get('institution_id') or 1)

        record = AnalysisModel.get_by_id(analysis_id, institution_id=inst_id, role=user_role)
        if not record:
            return jsonify({'success': False, 'error': 'Analysis record not found'}), 404
            
        html_bytes = ReportGenerator.generate_html_report(record)
        return Response(
            html_bytes,
            mimetype='text/html',
            headers={'Content-Disposition': f'attachment;filename=threat_report_{analysis_id}.html'}
        )
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to generate downloadable report.'}), 500
