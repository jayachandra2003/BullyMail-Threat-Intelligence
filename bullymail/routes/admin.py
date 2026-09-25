from flask import Blueprint, request, jsonify
from ..models.user import UserModel
from ..models.institution import InstitutionModel
from ..models.analysis import AnalysisModel
from ..services.admin_warning_service import admin_warning_service
from .auth import require_role

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/api/admin/pending-registrations', methods=['GET'])
@require_role('admin')
def get_pending_registrations(current_user):
    """Retrieves all pending account registration requests and user approval summary stats."""
    try:
        from ..database.connection import fetch_one
        pending_users = UserModel.get_pending_approval_users()
        
        approved_res = fetch_one("SELECT COUNT(*) as count FROM users WHERE status IN ('ACTIVE', 'APPROVED')")
        rejected_res = fetch_one("SELECT COUNT(*) as count FROM users WHERE status = 'REJECTED'")
        
        app_cnt = approved_res['count'] if (approved_res and 'count' in approved_res) else 0
        rej_cnt = rejected_res['count'] if (rejected_res and 'count' in rejected_res) else 0
        pnd_cnt = len(pending_users)
        tot_cnt = pnd_cnt + app_cnt + rej_cnt

        return jsonify({
            'success': True,
            'pending_users': pending_users,
            'pending_count': pnd_cnt,
            'approved_count': app_cnt,
            'rejected_count': rej_cnt,
            'total_count': tot_cnt
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to retrieve pending registrations: {e}"}), 500

@admin_bp.route('/api/admin/institutions', methods=['GET'])
@require_role('admin')
def list_institutions(current_user):
    """Lists all active institutions for tenant assignment."""
    try:
        institutions = InstitutionModel.list_all()
        return jsonify({'success': True, 'institutions': institutions})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to list institutions: {e}"}), 500

@admin_bp.route('/api/admin/approve-user', methods=['POST'])
@require_role('admin')
def approve_user(current_user):
    """
    Administrative approval endpoint.
    Approves/rejects pending users, provisions new institutions, or assigns existing institutions.
    """
    data = request.get_json() or {}
    user_id = data.get('user_id')
    action = data.get('action', 'approve').lower()
    provision_type = data.get('provision_type', 'assign_existing').lower()
    role = data.get('role', 'analyst').lower()

    if not user_id:
        return jsonify({'success': False, 'error': 'User ID is required.'}), 400

    target_user = UserModel.get_by_id(user_id)
    if not target_user:
        return jsonify({'success': False, 'error': 'Target user record not found.'}), 404

    if target_user.get('status') != 'PENDING_ADMIN_APPROVAL':
        return jsonify({'success': False, 'error': f"User account is not pending approval (Current status: {target_user.get('status')})."}), 400

    # Rejection workflow
    if action == 'reject':
        UserModel.reject_user(user_id)
        return jsonify({'success': True, 'message': f"Registration request for user '{target_user.get('username')}' has been rejected."})

    # Approval / Provisioning workflow
    if action != 'approve':
        return jsonify({'success': False, 'error': f"Invalid action '{action}'. Allowed actions: 'approve', 'reject'."}), 400

    target_inst_id = None

    if provision_type == 'create_new':
        inst_name = (data.get('institution_name') or target_user.get('requested_institution_name') or '').strip()
        inst_domain = (data.get('institution_domain') or target_user.get('requested_institution_domain') or '').strip()

        if not inst_name or not inst_domain:
            return jsonify({'success': False, 'error': 'Institution name and domain are required to provision a new institution.'}), 400

        try:
            target_inst_id = InstitutionModel.create_institution(inst_name, inst_domain)
        except ValueError as ve:
            return jsonify({'success': False, 'error': str(ve)}), 400

    elif provision_type == 'assign_existing':
        inst_id = data.get('institution_id')
        if not inst_id:
            return jsonify({'success': False, 'error': 'Institution ID must be specified for existing institution assignment.'}), 400

        existing_inst = InstitutionModel.get_by_id(inst_id)
        if not existing_inst:
            return jsonify({'success': False, 'error': f"Target institution ID {inst_id} does not exist."}), 404

        target_inst_id = inst_id

    else:
        return jsonify({'success': False, 'error': f"Invalid provision_type '{provision_type}'. Allowed types: 'create_new', 'assign_existing'."}), 400

    # Activate account with provisioned institution_id and assigned role
    valid_roles = {'admin', 'analyst', 'operator'}
    assigned_role = role if role in valid_roles else 'analyst'

    success = UserModel.provision_and_approve_user(user_id, target_inst_id, assigned_role)
    if not success:
        return jsonify({'success': False, 'error': 'Failed to update user provisioning state.'}), 500

    return jsonify({
        'success': True,
        'message': f"User '{target_user.get('username')}' provisioned and activated successfully.",
        'user_id': user_id,
        'institution_id': target_inst_id,
        'role': assigned_role,
        'status': 'ACTIVE'
    })

# =========================================================================
# Phase 1D Tenant-Scoped Mailbox Administration Endpoints
# =========================================================================

@admin_bp.route('/api/admin/mailboxes', methods=['GET'])
@require_role('admin')
def list_admin_mailboxes(current_user):
    """Lists all mailboxes belonging strictly to current_user['institution_id']."""
    try:
        inst_id = current_user.get('institution_id') or 1
        from ..services.email_service import email_service
        mailboxes = email_service.get_mailboxes_for_institution(inst_id)
        return jsonify({'success': True, 'mailboxes': mailboxes})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to list mailboxes: {e}"}), 500

@admin_bp.route('/api/admin/mailboxes/configure', methods=['POST'])
@require_role('admin')
def configure_admin_mailbox(current_user):
    """Configures a new tenant mailbox for current_user['institution_id']."""
    try:
        inst_id = current_user.get('institution_id') or 1

        data = request.get_json() or {}
        email_address = (data.get('email_address') or '').strip()
        app_password = (data.get('app_password') or '').strip()
        imap_server = (data.get('imap_server') or 'imap.gmail.com').strip()
        smtp_server = (data.get('smtp_server') or 'smtp.gmail.com').strip()
        smtp_port = data.get('smtp_port') or 587

        if not email_address or not app_password:
            return jsonify({'success': False, 'error': 'email_address and app_password are required.'}), 400

        from ..services.email_service import email_service
        mailbox = email_service.configure_mailbox(
            institution_id=inst_id,
            email_address=email_address,
            app_password=app_password,
            imap_server=imap_server,
            smtp_server=smtp_server,
            smtp_port=smtp_port
        )
        return jsonify({'success': True, 'message': 'Mailbox configured successfully.', 'mailbox': mailbox})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to configure mailbox: {e}"}), 500

@admin_bp.route('/api/admin/mailboxes/test-connection', methods=['POST'])
@require_role('admin')
def test_admin_mailbox_connection(current_user):
    """Runs pre-flight connection test using IMAP TLS. Never persists credentials."""
    try:
        data = request.get_json() or {}
        email_address = (data.get('email_address') or '').strip()
        app_password = (data.get('app_password') or '').strip()
        imap_server = (data.get('imap_server') or 'imap.gmail.com').strip()
        imap_port = data.get('imap_port') or 993

        if not email_address or not app_password:
            return jsonify({'success': False, 'error': 'email_address and app_password are required for pre-flight connection test.'}), 400

        from ..services.email_service import email_service
        success, message = email_service.test_preflight_connection(
            email_address=email_address,
            app_password=app_password,
            imap_server=imap_server,
            imap_port=imap_port
        )
        return jsonify({'success': success, 'message': message}), (200 if success else 400)
    except Exception as e:
        return jsonify({'success': False, 'error': f"Connection test error: {e}"}), 500

@admin_bp.route('/api/admin/mailboxes/<int:mailbox_id>/status', methods=['POST'])
@require_role('admin')
def update_admin_mailbox_status(current_user, mailbox_id):
    """Enables or disables a tenant-owned mailbox."""
    try:
        inst_id = current_user.get('institution_id') or 1

        data = request.get_json() or {}
        new_status = (data.get('status') or '').strip().lower()
        if new_status not in ('active', 'disabled', 'inactive'):
            return jsonify({'success': False, 'error': "Invalid status. Allowed values: 'active', 'disabled'."}), 400

        from ..services.email_service import email_service
        updated = email_service.update_mailbox_status(mailbox_id, inst_id, new_status)
        if not updated:
            return jsonify({'success': False, 'error': 'Mailbox not found.'}), 404

        return jsonify({'success': True, 'message': f"Mailbox status updated to '{new_status}'."})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to update mailbox status: {e}"}), 500

@admin_bp.route('/api/admin/mailboxes/<int:mailbox_id>', methods=['PUT', 'PATCH'])
@admin_bp.route('/api/admin/mailboxes/<int:mailbox_id>/update', methods=['POST'])
@require_role('admin')
def update_admin_mailbox_credentials(current_user, mailbox_id):
    """
    Updates credentials and settings for an existing tenant-owned mailbox (Admin Only).
    Preserves existing mailbox ID and preserves existing encrypted password if app_password is empty.
    """
    try:
        inst_id = current_user.get('institution_id') or 1

        data = request.get_json() or {}
        email_address = data.get('email_address') or data.get('email')
        app_password = data.get('app_password')
        imap_server = data.get('imap_server')
        smtp_server = data.get('smtp_server')
        smtp_port = data.get('smtp_port')

        from ..services.email_service import email_service
        updated_mb, msg = email_service.update_mailbox_credentials(
            mailbox_id=mailbox_id,
            institution_id=inst_id,
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
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to update mailbox credentials: {e}"}), 500

@admin_bp.route('/api/admin/mailboxes/<int:mailbox_id>', methods=['DELETE'])
@require_role('admin')
def delete_admin_mailbox(current_user, mailbox_id):
    """Deletes/removes a tenant-owned mailbox."""
    try:
        inst_id = current_user.get('institution_id') or 1

        from ..services.email_service import email_service
        success, message = email_service.delete_mailbox(mailbox_id, inst_id)
        if not success:
            status_code = 404 if 'not found' in message.lower() else 400
            return jsonify({'success': False, 'error': message}), status_code

        return jsonify({'success': True, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to delete mailbox: {e}"}), 500

@admin_bp.route('/api/admin/mailboxes/<int:mailbox_id>/sync', methods=['POST'])
@require_role('admin')
def sync_admin_mailbox(current_user, mailbox_id):
    """
    Synchronously triggers manual mailbox synchronization for tenant-owned mailbox.
    Acquires atomic sync lease, executes Phase 1B MailboxProcessor pipeline, and completes lease.
    """
    try:
        inst_id = current_user.get('institution_id') or 1

        from ..services.email_service import email_service
        mailbox = email_service.get_mailbox_by_id(mailbox_id, inst_id)
        if not mailbox:
            return jsonify({'success': False, 'error': 'Mailbox not found.'}), 404

        if mailbox.get('status') == 'disabled':
            return jsonify({'success': False, 'error': 'Cannot synchronize a disabled mailbox.'}), 400

        # Acquire atomic sync lease
        lease_id = email_service.acquire_sync_lease(mailbox_id, inst_id)
        if not lease_id:
            return jsonify({'success': False, 'error': 'Synchronization already in progress for this mailbox.'}), 409

        try:
            from ..worker.processor import MailboxProcessor
            processor = MailboxProcessor()
            success = processor.process_mailbox(mailbox, lease_id=lease_id)
            email_service.release_sync_lease(mailbox_id, lease_id, final_status=('OK' if success else 'ERROR'))
            return jsonify({
                'success': success,
                'message': 'Manual synchronization completed.' if success else 'Synchronization completed with errors.'
            }), (200 if success else 500)
        except Exception as proc_err:
            email_service.release_sync_lease(mailbox_id, lease_id, final_status='ERROR', last_error=str(proc_err))
            raise proc_err
    except Exception as e:
        return jsonify({'success': False, 'error': f"Synchronization error: {e}"}), 500

# =========================================================================
# Phase 2 Human-In-The-Loop Incident Review & Warning Endpoints (Admin Only)
# =========================================================================

def _get_scoped_analysis_record(current_user, analysis_id):
    """Retrieves analysis record enforcing tenant isolation boundaries."""
    inst_id = current_user.get('institution_id') or 1
    # Check if analysis exists and matches admin's institution
    record = AnalysisModel.get_by_id(analysis_id, institution_id=inst_id, role='admin')
    return record, inst_id

@admin_bp.route('/api/admin/analysis/<int:analysis_id>/warning-preview', methods=['GET'])
@require_role('admin')
def get_warning_preview(current_user, analysis_id):
    """
    Returns warning preview details, recipient, sender, advisory text,
    and current incident status for confirmation modal (Admin Only).
    """
    record, inst_id = _get_scoped_analysis_record(current_user, analysis_id)
    if not record:
        return jsonify({'success': False, 'error': 'Incident record not found or cross-tenant access denied.'}), 404

    preview = admin_warning_service.get_warning_preview(record)
    last_warning = AnalysisModel.get_last_warning_audit(analysis_id, institution_id=inst_id)

    b = record.get('bullying_analysis') or {}
    indicators = b.get('rule_based_matches') or []
    if not indicators and b.get('is_bullying'):
        indicators = ['NLP linguistic threat pattern']

    return jsonify({
        'success': True,
        'preview': preview,
        'is_already_sent': record.get('incident_status') == 'WARNING_SENT',
        'last_warning': last_warning,
        'incident_status': record.get('incident_status', 'PENDING_REVIEW'),
        'overall_risk_level': record.get('overall_risk_level', 'LOW'),
        'overall_confidence': record.get('overall_confidence', 0.0),
        'is_bullying': bool(b.get('is_bullying') or record.get('is_bullying')),
        'detected_indicators': indicators,
        'email_subject': record.get('email_subject', 'No Subject'),
        'email_from': record.get('email_from', 'Unknown'),
        'email_to': record.get('email_to', ''),
        'target_recipient': preview['target_recipient'],
        'warning_from': preview['from_display'],
        'warning_subject': preview['warning_subject'],
        'warning_body': preview['warning_body']
    })

@admin_bp.route('/api/admin/analysis/<int:analysis_id>/warning', methods=['POST'])
@require_role('admin')
def send_admin_warning(current_user, analysis_id):
    """
    Dispatches a professional advisory warning email to the original sender of a detected harmful email.
    Enforces duplicate send prevention, tenant isolation, and audit trail recording (Admin Only).
    """
    record, inst_id = _get_scoped_analysis_record(current_user, analysis_id)
    if not record:
        return jsonify({'success': False, 'error': 'Incident record not found or cross-tenant access denied.'}), 404

    # Duplicate warning prevention
    if record.get('incident_status') == 'WARNING_SENT':
        last_audit = AnalysisModel.get_last_warning_audit(analysis_id, institution_id=inst_id)
        admin_name = last_audit.get('admin_username') if last_audit else 'an administrator'
        sent_time = last_audit.get('created_at') if last_audit else 'previously'
        return jsonify({
            'success': False,
            'error': f'Warning email has already been dispatched for this incident by {admin_name} ({sent_time}).',
            'warning_already_sent': True,
            'status': 'WARNING_SENT'
        }), 400

    raw_from = record.get('email_from', '')
    target_recipient = admin_warning_service.extract_clean_email(raw_from)
    if not target_recipient or '@' not in target_recipient:
        return jsonify({
            'success': False,
            'error': f'Cannot dispatch warning: Original sender email "{raw_from}" is invalid or missing.'
        }), 400

    data = request.get_json() or {}
    custom_subject = data.get('subject')
    custom_body = data.get('body')

    preview = admin_warning_service.get_warning_preview(record)
    subject_to_send = (custom_subject or preview['warning_subject']).strip()
    body_to_send = (custom_body or preview['warning_body']).strip()

    # Dispatch outbound warning email via SMTP service
    mb_id = record.get('email_config_id')
    if mb_id is not None:
        send_ok, send_msg = admin_warning_service.send_warning_email(
            target_recipient,
            subject_to_send,
            body_to_send,
            institution_id=inst_id,
            mailbox_id=mb_id
        )
    else:
        send_ok, send_msg = admin_warning_service.send_warning_email(
            target_recipient,
            subject_to_send,
            body_to_send,
            institution_id=inst_id
        )

    if not send_ok:
        # Failed transmission: do NOT mark incident as WARNING_SENT
        AnalysisModel.record_audit_action(
            analysis_id=analysis_id,
            institution_id=inst_id,
            admin_id=current_user.get('id', 1),
            admin_username=current_user.get('username', 'admin'),
            action='WARNING_ATTEMPT_FAILED',
            original_sender=raw_from,
            original_recipient=record.get('email_to'),
            warning_recipient=target_recipient,
            warning_subject=subject_to_send,
            delivery_status='FAILED',
            reason=send_msg
        )
        return jsonify({'success': False, 'error': f"Failed to send warning email: {send_msg}"}), 500

    # Successful transmission: Update incident status to WARNING_SENT
    AnalysisModel.update_incident_status(analysis_id, 'WARNING_SENT', institution_id=inst_id)

    # Record immutable audit log entry
    AnalysisModel.record_audit_action(
        analysis_id=analysis_id,
        institution_id=inst_id,
        admin_id=current_user.get('id', 1),
        admin_username=current_user.get('username', 'admin'),
        action='WARNING_SENT',
        original_sender=raw_from,
        original_recipient=record.get('email_to'),
        warning_recipient=target_recipient,
        warning_subject=subject_to_send,
        delivery_status='SUCCESS',
        reason='Advisory warning email dispatched to original sender following administrative review.'
    )

    return jsonify({
        'success': True,
        'message': f'Warning email sent successfully to original sender ({target_recipient}).',
        'status': 'WARNING_SENT',
        'warning_recipient': target_recipient
    })

@admin_bp.route('/api/admin/analysis/<int:analysis_id>/review', methods=['POST'])
@require_role('admin')
def mark_incident_reviewed(current_user, analysis_id):
    """Marks an incident as reviewed without sending an email (Admin Only)."""
    record, inst_id = _get_scoped_analysis_record(current_user, analysis_id)
    if not record:
        return jsonify({'success': False, 'error': 'Incident record not found or cross-tenant access denied.'}), 404

    data = request.get_json() or {}
    note = (data.get('note') or data.get('reason') or '').strip()

    AnalysisModel.update_incident_status(analysis_id, 'REVIEWED', institution_id=inst_id)
    AnalysisModel.record_audit_action(
        analysis_id=analysis_id,
        institution_id=inst_id,
        admin_id=current_user.get('id', 1),
        admin_username=current_user.get('username', 'admin'),
        action='REVIEWED',
        original_sender=record.get('email_from'),
        original_recipient=record.get('email_to'),
        delivery_status='SUCCESS',
        reason=note or 'Incident reviewed and acknowledged by administrator.'
    )

    return jsonify({
        'success': True,
        'message': 'Incident status updated to REVIEWED.',
        'status': 'REVIEWED'
    })

@admin_bp.route('/api/admin/analysis/<int:analysis_id>/false-positive', methods=['POST'])
@require_role('admin')
def mark_incident_false_positive(current_user, analysis_id):
    """Marks an incident as a false positive with an optional reason classification (Admin Only)."""
    record, inst_id = _get_scoped_analysis_record(current_user, analysis_id)
    if not record:
        return jsonify({'success': False, 'error': 'Incident record not found or cross-tenant access denied.'}), 404

    data = request.get_json() or {}
    reason = (data.get('reason') or data.get('category') or 'Model false positive').strip()
    notes = (data.get('notes') or '').strip()
    full_reason = f"{reason}: {notes}" if notes else reason

    AnalysisModel.update_incident_status(analysis_id, 'FALSE_POSITIVE', institution_id=inst_id)
    AnalysisModel.record_audit_action(
        analysis_id=analysis_id,
        institution_id=inst_id,
        admin_id=current_user.get('id', 1),
        admin_username=current_user.get('username', 'admin'),
        action='FALSE_POSITIVE',
        original_sender=record.get('email_from'),
        original_recipient=record.get('email_to'),
        delivery_status='SUCCESS',
        reason=full_reason
    )

    return jsonify({
        'success': True,
        'message': 'Incident marked as FALSE POSITIVE.',
        'status': 'FALSE_POSITIVE',
        'reason': reason
    })
