from flask import Blueprint, request, jsonify, session
from ..database.connection import fetch_one
from ..services.email_service import EmailService
from ..services.risk_engine import UnifiedRiskEngine
from ..models.analysis import AnalysisModel
from ..worker.processor import MailboxProcessor
from .auth import get_current_user, require_role

from ..models.institution import InstitutionModel

email_bp = Blueprint('email', __name__)
email_service = EmailService()
risk_engine = UnifiedRiskEngine()
mailbox_processor = MailboxProcessor(risk_engine=risk_engine)

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

def _iso(val):
    if not val:
        return None
    return val.isoformat() if hasattr(val, 'isoformat') else str(val)

@email_bp.route('/api/institutions', methods=['GET'])
@require_role('admin', 'analyst')
def get_institutions(current_user):
    user_role = current_user.get('role', 'analyst')
    user_inst_id = current_user.get('institution_id') or 1

    if user_role == 'admin':
        insts = InstitutionModel.list_all()
    else:
        inst = InstitutionModel.get_by_id(user_inst_id)
        insts = [inst] if inst else []
        
    return jsonify({'success': True, 'institutions': insts})

@email_bp.route('/api/institutions/<int:inst_id>/stats', methods=['GET'])
@require_role('admin', 'analyst')
def get_institution_stats(current_user, inst_id):
    target_id, err_resp = _resolve_target_institution_id(current_user, inst_id, strict_403=True)
    if err_resp:
        msg, code = err_resp
        return jsonify({'success': False, 'error': msg}), code

    stats = InstitutionModel.get_stats(target_id)
    inst = InstitutionModel.get_by_id(target_id)
    return jsonify({
        'success': True,
        'institution': inst,
        'stats': stats
    })

@email_bp.route('/api/institutions/<int:inst_id>/mailboxes', methods=['GET'])
@require_role('admin', 'analyst')
def get_institution_mailboxes(current_user, inst_id):
    target_id, err_resp = _resolve_target_institution_id(current_user, inst_id, strict_403=True)
    if err_resp:
        msg, code = err_resp
        return jsonify({'success': False, 'error': msg}), code

    mailboxes = email_service.get_mailboxes_for_institution(target_id)
    sanitized = []
    for m in mailboxes:
        mb_id = m.get('id')
        provider = 'Gmail' if 'gmail' in (m.get('email_address') or '').lower() else 'Custom IMAP'
        sanitized.append({
            'id': mb_id,
            'institution_id': m.get('institution_id'),
            'email_address': m.get('email_address'),
            'provider': provider,
            'imap_server': m.get('imap_server'),
            'smtp_server': m.get('smtp_server'),
            'smtp_port': m.get('smtp_port'),
            'status': m.get('status', 'active'),
            'sync_status': m.get('sync_status', 'IDLE'),
            'last_synced_at': _iso(m.get('last_synced_at')),
            'last_error': m.get('last_error'),
            'total_ingested_count': m.get('total_ingested_count') or 0,
            'configured_at': _iso(m.get('configured_at'))
        })
    return jsonify({'success': True, 'institution_id': target_id, 'mailboxes': sanitized})

@email_bp.route('/api/institutions/<int:inst_id>/mailboxes/<int:mailbox_id>', methods=['PUT', 'PATCH'])
@require_role('admin')
def update_institution_mailbox_credentials(current_user, inst_id, mailbox_id):
    target_id, err_resp = _resolve_target_institution_id(current_user, inst_id, strict_403=True)
    if err_resp:
        msg, code = err_resp
        return jsonify({'success': False, 'error': msg}), code

    data = request.get_json() or {}
    email_address = data.get('email_address') or data.get('email')
    app_password = data.get('app_password')
    imap_server = data.get('imap_server')
    smtp_server = data.get('smtp_server')
    smtp_port = data.get('smtp_port')

    updated_mb, msg = email_service.update_mailbox_credentials(
        mailbox_id=mailbox_id,
        institution_id=target_id,
        email_address=email_address,
        app_password=app_password,
        imap_server=imap_server,
        smtp_server=smtp_server,
        smtp_port=smtp_port
    )

    if not updated_mb:
        status_code = 404 if 'not found' in msg.lower() else 403
        return jsonify({'success': False, 'error': msg}), status_code

    return jsonify({
        'success': True,
        'message': msg,
        'mailbox': updated_mb
    })

@email_bp.route('/api/mailboxes', methods=['GET'])
@require_role('admin', 'analyst')
def get_mailboxes(current_user):
    req_inst = request.args.get('institution_id')
    target_id, err_resp = _resolve_target_institution_id(current_user, req_inst)
    if err_resp:
        msg, code = err_resp
        return jsonify({'success': False, 'error': msg}), code

    mailboxes = email_service.get_mailboxes_for_institution(target_id)
    sanitized = []
    for m in mailboxes:
        mb_id = m.get('id')
        provider = 'Gmail' if 'gmail' in (m.get('email_address') or '').lower() else 'Custom IMAP'
        sanitized.append({
            'id': mb_id,
            'institution_id': m.get('institution_id'),
            'email_address': m.get('email_address'),
            'provider': provider,
            'imap_server': m.get('imap_server'),
            'smtp_server': m.get('smtp_server'),
            'smtp_port': m.get('smtp_port'),
            'status': m.get('status', 'active'),
            'sync_status': m.get('sync_status', 'IDLE'),
            'last_synced_at': _iso(m.get('last_synced_at')),
            'last_error': m.get('last_error'),
            'total_ingested_count': m.get('total_ingested_count') or 0,
            'configured_at': _iso(m.get('configured_at'))
        })
    return jsonify({'success': True, 'institution_id': target_id, 'mailboxes': sanitized})

@email_bp.route('/api/mailbox/<int:mailbox_id>', methods=['GET'])
@require_role('admin', 'analyst')
def get_mailbox(current_user, mailbox_id):
    req_inst = request.args.get('institution_id')
    target_id, err_resp = _resolve_target_institution_id(current_user, req_inst)
    if err_resp:
        msg, code = err_resp
        return jsonify({'success': False, 'error': msg}), code

    mb = email_service.get_mailbox_by_id(mailbox_id, target_id)
    if not mb:
        return jsonify({'success': False, 'error': 'Mailbox not found'}), 404

    provider = 'Gmail' if 'gmail' in (mb.get('email_address') or '').lower() else 'Custom IMAP'
    sanitized = {
        'id': mb.get('id'),
        'institution_id': mb.get('institution_id'),
        'email_address': mb.get('email_address'),
        'provider': provider,
        'imap_server': mb.get('imap_server'),
        'smtp_server': mb.get('smtp_server'),
        'smtp_port': mb.get('smtp_port'),
        'status': mb.get('status', 'active'),
        'sync_status': mb.get('sync_status', 'IDLE'),
        'last_synced_at': _iso(mb.get('last_synced_at')),
        'last_error': mb.get('last_error'),
        'total_ingested_count': mb.get('total_ingested_count') or 0,
        'configured_at': _iso(mb.get('configured_at'))
    }
    return jsonify({'success': True, 'mailbox': sanitized})

@email_bp.route('/api/mailboxes/<int:mailbox_id>/emails', methods=['GET'])
@require_role('admin', 'analyst')
def get_mailbox_emails(current_user, mailbox_id):
    """Retrieves emails belonging strictly to the specified mailbox (Mailbox & Tenant Isolation Enforced)."""
    req_inst = request.args.get('institution_id')
    target_id, err_resp = _resolve_target_institution_id(current_user, req_inst)
    if err_resp:
        msg, code = err_resp
        return jsonify({'success': False, 'error': msg}), code

    mb = email_service.get_mailbox_by_id(mailbox_id, target_id)
    if not mb:
        return jsonify({'success': False, 'error': 'Mailbox not found or access denied'}), 404

    try:
        limit = min(int(request.args.get('limit', 50)), 500)
    except (ValueError, TypeError):
        limit = 50

    search = request.args.get('search')
    risk_filter = request.args.get('risk')

    provider = 'Gmail' if 'gmail' in (mb.get('email_address') or '').lower() else 'Custom IMAP'
    sanitized_mb = {
        'id': mb.get('id'),
        'institution_id': mb.get('institution_id'),
        'email_address': mb.get('email_address'),
        'provider': provider,
        'imap_server': mb.get('imap_server'),
        'smtp_server': mb.get('smtp_server'),
        'smtp_port': mb.get('smtp_port'),
        'status': mb.get('status', 'active'),
        'sync_status': mb.get('sync_status', 'IDLE'),
        'last_synced_at': _iso(mb.get('last_synced_at')),
        'last_error': mb.get('last_error'),
        'total_ingested_count': mb.get('total_ingested_count') or 0,
        'configured_at': _iso(mb.get('configured_at'))
    }

    emails = AnalysisModel.get_mailbox_emails(mailbox_id=mailbox_id, institution_id=target_id, limit=limit, search=search, risk_filter=risk_filter)
    return jsonify({'success': True, 'mailbox': sanitized_mb, 'emails': emails})

@email_bp.route('/api/mailbox/test', methods=['POST'])
@require_role('admin')
def test_new_mailbox_connection(current_user):
    data = request.get_json() or {}
    email_address = data.get('email_address', '').strip()
    app_password = data.get('app_password', '').strip()
    imap_server = data.get('imap_server', 'imap.gmail.com').strip()

    if not email_address or not app_password:
        return jsonify({'success': False, 'error': 'Email address and App Password are required'}), 400

    success, message = email_service.test_preflight_connection(email_address, app_password, imap_server=imap_server)
    return jsonify({'success': success, 'message': message})

@email_bp.route('/api/mailbox/<int:mailbox_id>/test', methods=['POST'])
@require_role('admin')
def test_existing_mailbox_connection(current_user, mailbox_id):
    inst_id = current_user.get('institution_id') or 1

    mb = email_service.get_mailbox_by_id(mailbox_id, inst_id)
    if not mb:
        return jsonify({'success': False, 'error': 'Mailbox not found'}), 404

    success, message = email_service.test_connection(institution_id=inst_id)
    return jsonify({'success': success, 'message': message})

@email_bp.route('/api/mailbox', methods=['POST'])
@require_role('admin')
def create_mailbox(current_user):
    data = request.get_json() or {}
    email_address = data.get('email_address', '').strip()
    app_password = data.get('app_password', '').strip()
    imap_server = data.get('imap_server', 'imap.gmail.com').strip()
    smtp_server = data.get('smtp_server', 'smtp.gmail.com').strip()
    smtp_port = data.get('smtp_port', 587)

    if not email_address or not app_password:
        return jsonify({'success': False, 'error': 'Email address and App Password are required'}), 400

    req_inst_id = data.get('institution_id')
    inst_id, err_resp = _resolve_target_institution_id(current_user, req_inst_id)
    if err_resp:
        msg, code = err_resp
        return jsonify({'success': False, 'error': msg}), code

    # 1. Pre-flight connection test
    test_ok, test_msg = email_service.test_preflight_connection(email_address, app_password, imap_server=imap_server)
    if not test_ok:
        return jsonify({'success': False, 'error': 'Connection test failed', 'details': test_msg}), 400

    # 2. Configure mailbox with Fernet encryption
    mailbox = email_service.configure_mailbox(
        institution_id=inst_id,
        email_address=email_address,
        app_password=app_password,
        imap_server=imap_server,
        smtp_server=smtp_server,
        smtp_port=smtp_port
    )
    return jsonify({
        'success': True,
        'message': 'Mailbox configured and verified successfully.',
        'mailbox_id': mailbox.get('id')
    })

@email_bp.route('/api/mailbox/<int:mailbox_id>/sync', methods=['POST'])
@email_bp.route('/api/mailboxes/<int:mailbox_id>/sync', methods=['POST'])
@require_role('admin')
def sync_mailbox(current_user, mailbox_id):
    mb = fetch_one("SELECT * FROM email_config WHERE id = %s", (mailbox_id,))
    if not mb:
        return jsonify({'success': False, 'error': 'Mailbox not found'}), 404

    inst_id = mb.get('institution_id') or 1
    if mb.get('status') == 'disabled':
        return jsonify({'success': False, 'error': 'Cannot sync a disabled mailbox.'}), 400

    lease_id = email_service.acquire_sync_lease(mailbox_id, inst_id)
    if not lease_id:
        return jsonify({'success': False, 'error': 'Synchronization lease currently held by another process. Please wait.'}), 409

    summary = None
    try:
        summary = mailbox_processor.process_mailbox(mb, lease_id=lease_id, return_summary=True)
        return jsonify(summary)
    except Exception as e:
        return jsonify({
            'success': False,
            'emails_found': 0,
            'emails_processed': 0,
            'threats_detected': 0,
            'duplicates_skipped': 0,
            'failures': 1,
            'status': 'ERROR',
            'error': str(e)
        }), 500
    finally:
        final_status = 'OK' if (summary and summary.get('success')) else 'ERROR'
        last_err = (summary.get('error') if summary else None)
        email_service.release_sync_lease(mailbox_id, lease_id, final_status=final_status, last_error=last_err)

@email_bp.route('/api/institutions/<int:inst_id>/sync-all', methods=['POST'])
@require_role('admin')
def sync_all_institution_mailboxes(current_user, inst_id):
    user_inst = current_user.get('institution_id') or 1
    if user_inst != inst_id and current_user.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized institution access'}), 403

    mailboxes = email_service.get_mailboxes_for_institution(inst_id)
    active_mailboxes = [m for m in mailboxes if m.get('status') == 'active']

    results = []
    total_processed = 0
    total_threats = 0
    total_dupes = 0
    failures = 0

    for mb in active_mailboxes:
        mb_id = mb['id']
        lease_id = email_service.acquire_sync_lease(mb_id, inst_id)
        if not lease_id:
            results.append({'mailbox_id': mb_id, 'status': 'SKIPPED_LOCKED'})
            continue

        summary = None
        try:
            summary = mailbox_processor.process_mailbox(mb, lease_id=lease_id, return_summary=True)
            if summary.get('success'):
                total_processed += summary.get('emails_processed', 0)
                total_threats += summary.get('threats_detected', 0)
                total_dupes += summary.get('duplicates_skipped', 0)
            else:
                failures += 1
            results.append(summary)
        except Exception as e:
            failures += 1
            results.append({'mailbox_id': mb_id, 'status': 'ERROR', 'error': str(e)})
        finally:
            final_status = 'OK' if (summary and summary.get('success')) else 'ERROR'
            last_err = (summary.get('error') if summary else None)
            email_service.release_sync_lease(mb_id, lease_id, final_status=final_status, last_error=last_err)

    return jsonify({
        'success': True,
        'mailboxes_processed': len(active_mailboxes),
        'total_emails_processed': total_processed,
        'total_threats_detected': total_threats,
        'total_duplicates_skipped': total_dupes,
        'failures': failures,
        'details': results
    })

@email_bp.route('/api/mailbox/<int:mailbox_id>/enable', methods=['POST'])
@require_role('admin')
def enable_mailbox(current_user, mailbox_id):
    mb = fetch_one("SELECT institution_id FROM email_config WHERE id = %s", (mailbox_id,))
    if not mb:
        return jsonify({'success': False, 'error': 'Mailbox not found'}), 404
    inst_id = mb.get('institution_id')
    user_inst = current_user.get('institution_id')
    if user_inst and user_inst != inst_id and current_user.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized institution access'}), 403

    ok = email_service.update_mailbox_status(mailbox_id, inst_id, 'active')
    if not ok:
        return jsonify({'success': False, 'error': 'Mailbox not found'}), 404
    return jsonify({'success': True, 'message': 'Mailbox enabled successfully.'})

@email_bp.route('/api/mailbox/<int:mailbox_id>/disable', methods=['POST'])
@require_role('admin')
def disable_mailbox(current_user, mailbox_id):
    mb = fetch_one("SELECT institution_id FROM email_config WHERE id = %s", (mailbox_id,))
    if not mb:
        return jsonify({'success': False, 'error': 'Mailbox not found'}), 404
    inst_id = mb.get('institution_id')
    user_inst = current_user.get('institution_id')
    if user_inst and user_inst != inst_id and current_user.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized institution access'}), 403

    ok = email_service.update_mailbox_status(mailbox_id, inst_id, 'disabled')
    if not ok:
        return jsonify({'success': False, 'error': 'Mailbox not found'}), 404
    return jsonify({'success': True, 'message': 'Mailbox disabled successfully.'})

@email_bp.route('/api/configure-email', methods=['POST'])
@require_role('admin')
def configure_email(current_user):
    data = request.get_json() or {}
    email_address = data.get('email', '').strip()
    app_password = data.get('app_password', '').strip()
    
    if not email_address or not app_password:
        return jsonify({'success': False, 'error': 'Email address and App Password are required'}), 400
        
    inst_id = current_user.get('institution_id')
    if not inst_id:
        return jsonify({'success': False, 'error': 'Authenticated user is not assigned to an institution.'}), 400
    email_service.configure(email_address, app_password, institution_id=inst_id)
    success, message = email_service.test_connection(institution_id=inst_id)
    
    if success:
        return jsonify({
            'success': True,
            'email': email_address,
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
@require_role('admin')
def test_connection(current_user):
    inst_id = current_user.get('institution_id')
    if not inst_id:
        return jsonify({'success': False, 'error': 'Authenticated user is not assigned to an institution.'}), 400
    success, message = email_service.test_connection(institution_id=inst_id)
    return jsonify({
        'success': success,
        'message': message,
        'configured': success
    })

@email_bp.route('/api/send-test-email', methods=['POST'])
@require_role('admin')
def send_test_email(current_user):
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
