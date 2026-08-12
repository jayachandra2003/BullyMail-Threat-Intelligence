import io
from flask import Blueprint, request, jsonify, session, send_file, Response
from ..services.report_generator import ReportGenerator
from ..models.analysis import AnalysisModel

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/api/reports/download-csv', methods=['GET'])
def download_csv():
    """Generates and downloads a CSV export of analysis records."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        analyses = AnalysisModel.get_history(limit=500)
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
    """Renders a standalone printable HTML threat report."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        record = AnalysisModel.get_by_id(analysis_id)
        if not record:
            return "Report not found", 404
            
        html_bytes = ReportGenerator.generate_html_report(record)
        return Response(html_bytes, mimetype='text/html')
    except Exception:
        return "An error occurred while generating the security report.", 500

@reports_bp.route('/api/reports/download/<int:analysis_id>', methods=['GET'])
def download_report(analysis_id):
    """Downloads the standalone HTML security audit report."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        record = AnalysisModel.get_by_id(analysis_id)
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
