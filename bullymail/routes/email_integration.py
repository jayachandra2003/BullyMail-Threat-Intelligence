from flask import Blueprint, request, jsonify, session
from ..services.email_service import EmailService
from ..services.risk_engine import UnifiedRiskEngine
from ..models.analysis import AnalysisModel

email_bp = Blueprint('email', __name__)
email_service = EmailService()
risk_engine = UnifiedRiskEngine()

@email_bp.route('/api/configure-email', methods=['POST'])
def configure_email():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    data = request.get_json() or {}
    email_address = data.get('email', '').strip()
    app_password = data.get('app_password', '').strip()
    
    if not email_address or not app_password:
        return jsonify({'success': False, 'error': 'Email address and App Password are required'}), 400
        
    email_service.configure(email_address, app_password)
    success, message = email_service.test_connection()
    
    if success:
        return jsonify({
            'success': True,
            'message': 'Email configuration verified and saved successfully.',
            'test_result': message
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Email configuration failed',
            'details': message
        })

@email_bp.route('/api/test-email-connection', methods=['GET'])
def test_connection():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    success, message = email_service.test_connection()
    return jsonify({
        'success': success,
        'message': message,
        'configured': bool(email_service._email and email_service._password)
    })

@email_bp.route('/api/send-test-email', methods=['POST'])
def send_test_email():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    data = request.get_json() or {}
    to_email = data.get('to_email') or email_service._email
    
    success, message = email_service.send_email(
        to_email=to_email,
        subject="Test Alert: BullyMail Security System",
        body="This is an automated test communication confirming that BullyMail email integration is functioning properly."
    )
    return jsonify({'success': success, 'message': message})

@email_bp.route('/api/fetch-emails', methods=['POST'])
def fetch_emails():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    data = request.get_json() or {}
    mailbox = data.get('mailbox', 'INBOX')
    limit = min(int(data.get('limit', 10)), 20)
    
    try:
        raw_emails = email_service.fetch_emails(mailbox=mailbox, limit=limit)
        analyzed_emails = []
        
        for email_item in raw_emails:
            # Run Unified Risk Engine on fetched email
            report = risk_engine.analyze_email(
                email_text=email_item['body'],
                email_subject=email_item['subject'],
                email_from=email_item['from'],
                email_to=email_item.get('to', ''),
                attachments=email_item.get('attachments', []),
                images=email_item.get('images', [])
            )
            
            # Save to Database
            saved_id = AnalysisModel.save_analysis(report)
            report['id'] = saved_id
            
            # Format combined object
            analyzed_email = {
                'id': email_item.get('id'),
                'subject': email_item['subject'],
                'from': email_item['from'],
                'date': email_item['date'],
                'body': email_item['body'],
                'analysis': {
                    'is_bullying': report['bullying_analysis']['is_bullying'],
                    'confidence': report['bullying_analysis']['confidence'],
                    'rule_based_matches': report['bullying_analysis']['rule_based_matches'],
                    'rule_based_score': report['bullying_analysis']['rule_based_score'],
                    'ml_prediction': report['bullying_analysis']['ml_prediction'],
                    'ml_confidence': report['bullying_analysis']['ml_confidence'],
                    'model_used': report['bullying_analysis']['model_used']
                },
                'report': report
            }
            analyzed_emails.append(analyzed_email)
            
        return jsonify({'success': True, 'emails': analyzed_emails})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to process remote mailbox emails.'}), 500

@email_bp.route('/api/email-instructions')
def get_instructions():
    return jsonify({
        'success': True,
        'instructions': {
            'gmail_instructions': [
                "1. Enable 2-Step Verification in your Google Account.",
                "2. Go to Google Account -> Security -> App Passwords.",
                "3. Select 'Mail' and create a 16-character App Password.",
                "4. Enter the generated App Password (not your primary password)."
            ],
            'outlook_instructions': [
                "1. Enable 2FA in Microsoft Account Security settings.",
                "2. Generate an App Password for IMAP / SMTP access."
            ]
        }
    })
