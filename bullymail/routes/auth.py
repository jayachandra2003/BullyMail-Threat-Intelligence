import time
from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, make_response
from ..models.user import UserModel
from ..models.institution import InstitutionModel
from ..services.rate_limiter import auth_rate_limiter
from ..services.auth_token_service import AuthTokenService
from ..services.auth_email_service import auth_email_service
from ..services.captcha_service import CaptchaService

auth_bp = Blueprint('auth', __name__)

def _get_client_ip():
    """Extracts client IP considering potential proxy forwarding."""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

# =========================================================================
# 1. SIGNUP & REGISTRATION
# =========================================================================

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET' and 'user_id' in session:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        client_ip = _get_client_ip()

        # Support JSON & Form payloads
        if request.is_json:
            data = request.get_json() or {}
            username = (data.get('username') or '').strip()
            full_name = (data.get('full_name') or data.get('admin_name') or '').strip()
            email = (data.get('email') or '').strip()
            password = data.get('password') or ''
            confirm_password = data.get('confirm_password') or ''
            captcha_token = data.get('captcha_token') or ''
            requested_inst_name = (data.get('organization_name') or data.get('institution_name') or data.get('requested_institution_name') or '').strip()
            requested_inst_domain = (data.get('organization_domain') or data.get('institution_domain') or data.get('requested_institution_domain') or '').strip()
            requested_inst_type = (data.get('organization_type') or data.get('org_type') or 'university').strip().lower()
        else:
            username = (request.form.get('username') or '').strip()
            full_name = (request.form.get('full_name') or request.form.get('admin_name') or '').strip()
            email = (request.form.get('email') or '').strip()
            password = request.form.get('password') or ''
            confirm_password = request.form.get('confirm_password') or ''
            captcha_token = request.form.get('captcha_token') or ''
            requested_inst_name = (request.form.get('organization_name') or request.form.get('institution_name') or request.form.get('requested_institution_name') or '').strip()
            requested_inst_domain = (request.form.get('organization_domain') or request.form.get('institution_domain') or request.form.get('requested_institution_domain') or '').strip()
            requested_inst_type = (request.form.get('organization_type') or request.form.get('org_type') or 'university').strip().lower()

        # Rate Limit Check
        is_locked, retry_after = auth_rate_limiter.is_locked(client_ip, email, action='signup')
        if is_locked:
            minutes = max(1, (retry_after + 59) // 60)
            err_msg = f"Too many registration requests from this source. Please try again in {minutes} minute(s)."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg, 'retry_after': retry_after}), 429
            return render_template('signup.html', error=err_msg), 429

        # CAPTCHA Check if required
        if CaptchaService.is_enabled() or auth_rate_limiter.requires_captcha(client_ip, email, action='signup'):
            valid_cap, cap_err = CaptchaService.verify_token(captcha_token, client_ip)
            if not valid_cap:
                auth_rate_limiter.record_failure(client_ip, email, action='signup')
                if request.is_json:
                    return jsonify({'success': False, 'error': cap_err}), 400
                return render_template('signup.html', error=cap_err), 400

        # Input Validations
        if not username or not email or not password:
            if request.is_json:
                return jsonify({'success': False, 'error': 'All fields are required.'}), 400
            return render_template('signup.html', error='All fields are required.'), 400

        if not UserModel.validate_email_format(email):
            if request.is_json:
                return jsonify({'success': False, 'error': 'Please provide a valid email address.'}), 400
            return render_template('signup.html', error='Please provide a valid email address.'), 400

        is_match, match_err = UserModel.validate_password_confirmation(password, confirm_password)
        if not is_match:
            if request.is_json:
                return jsonify({'success': False, 'error': match_err}), 400
            return render_template('signup.html', error=match_err), 400

        is_valid_pw, pw_err = UserModel.validate_password_policy(password)
        if not is_valid_pw:
            if request.is_json:
                return jsonify({'success': False, 'error': pw_err}), 400
            return render_template('signup.html', error=pw_err), 400

        # Uniform Account Creation & User Enumeration Defense
        clean_email = UserModel.normalize_email(email)
        existing_user_email = UserModel.get_by_email(clean_email)
        existing_user_name = UserModel.get_by_username(username)

        # Standard anti-enumeration response
        success_msg = (
            "Registration submitted successfully! If this email is eligible for an account, "
            "a verification link has been dispatched to your inbox. Please check your email to activate access."
        )

        if existing_user_email or existing_user_name:
            # Check if this email already exists and is in PENDING_EMAIL_VERIFICATION status.
            # If so, the user is re-registering or retrying after not receiving/verifying the initial email.
            # Re-dispatch a fresh single-use verification token to their inbox so they can activate access.
            if existing_user_email and existing_user_email.get('status') == 'PENDING_EMAIL_VERIFICATION':
                # Allow re-verification if username matches or if requested username is not claimed by another user
                if not existing_user_name or existing_user_name.get('id') == existing_user_email.get('id'):
                    try:
                        UserModel.set_password(existing_user_email['id'], password)
                        raw_token = AuthTokenService.generate_email_verification_token(existing_user_email['id'])
                        verify_url = auth_email_service.get_verification_url(raw_token)
                        email_result = auth_email_service.send_verification_email(
                            clean_email, raw_token, existing_user_email.get('username') or username
                        )
                        if isinstance(email_result, tuple):
                            email_sent, email_message = email_result
                        else:
                            email_sent, email_message = bool(email_result), ""

                        import logging
                        auth_logger = logging.getLogger("bullymail.auth")
                        masked_email = clean_email[:3] + "***@" + clean_email.split('@')[-1] if '@' in clean_email else "***"
                        auth_logger.info(f"[REGISTRATION EMAIL] Re-attempting verification dispatch for existing pending user recipient={masked_email}")

                        if not email_sent:
                            auth_logger.error(
                                f"[REGISTRATION EMAIL] [FINAL_RESULT] FAILED for {masked_email}: {email_message}"
                            )
                            auth_logger.info(
                                f"[REGISTRATION EMAIL] [ACTIVATION_LINK] User {masked_email} activation URL: {verify_url}"
                            )
                            auth_rate_limiter.record_failure(client_ip, clean_email, action='signup')
                            fail_msg = "Your account was created, but we could not send the verification email. Please try again."
                            if request.is_json:
                                return jsonify({'success': False, 'error': fail_msg, 'status': 'PENDING_EMAIL_VERIFICATION', 'verification_url': verify_url}), 500
                            return render_template('signup.html', error=fail_msg, verification_link=verify_url), 500

                        auth_logger.info(f"[REGISTRATION EMAIL] [FINAL_RESULT] SUCCESS: re-sent to {masked_email}")
                        auth_rate_limiter.record_success(client_ip, clean_email, action='signup')
                        if request.is_json:
                            return jsonify({'success': True, 'message': success_msg, 'status': 'PENDING_VERIFICATION'})
                        return render_template('signup.html', success=success_msg)
                    except Exception as ex:
                        import logging
                        logging.getLogger("bullymail.auth").error(f"[REGISTRATION EMAIL] Error during verification resend: {ex}")

            # Simulate work to prevent timing enumeration for fully active or admin-pending accounts
            UserModel.hash_password(password)
            auth_rate_limiter.record_failure(client_ip, clean_email, action='signup')
            if request.is_json:
                return jsonify({'success': True, 'message': success_msg, 'status': 'PENDING_VERIFICATION'})
            return render_template('signup.html', success=success_msg)

        try:
            # Resolve or provision pending institution
            target_inst_id = None
            resolved_domain = requested_inst_domain or (clean_email.split('@')[-1] if '@' in clean_email else None)
            resolved_org_name = requested_inst_name or (f"{resolved_domain.split('.')[0].capitalize()} Organization" if resolved_domain else f"{username.capitalize()}'s Organization")

            if resolved_domain:
                existing_inst = InstitutionModel.get_by_domain(resolved_domain)
                if existing_inst:
                    target_inst_id = existing_inst['id']
                else:
                    try:
                        target_inst_id = InstitutionModel.create_institution(
                            name=resolved_org_name,
                            domain=resolved_domain,
                            org_type=requested_inst_type,
                            contact_name=full_name or username,
                            contact_email=clean_email,
                            status='PENDING_APPROVAL'
                        )
                    except Exception:
                        pass

            user_id = UserModel.create_user(
                username=username,
                password=password,
                email=clean_email,
                role='org_admin',
                status='PENDING_EMAIL_VERIFICATION',
                institution_id=None,
                requested_institution_name=resolved_org_name,
                requested_institution_domain=resolved_domain,
                full_name=full_name or username
            )

            # Ensure user_id was retrieved
            if not user_id:
                existing = UserModel.get_by_email(clean_email) or UserModel.get_by_username(username)
                if existing:
                    user_id = existing.get('id')

            # Generate single-use verification token
            raw_token = AuthTokenService.generate_email_verification_token(user_id)
            verify_url = auth_email_service.get_verification_url(raw_token)
            import logging
            auth_logger = logging.getLogger("bullymail.auth")
            masked_email = clean_email[:3] + "***@" + clean_email.split('@')[-1] if '@' in clean_email else "***"
            auth_logger.info(f"[REGISTRATION EMAIL] New account created (user_id={user_id}). Dispatching verification email to recipient={masked_email}")

            email_result = auth_email_service.send_verification_email(clean_email, raw_token, username)
            if isinstance(email_result, tuple):
                email_sent, email_message = email_result
            else:
                email_sent, email_message = bool(email_result), ""

            if not email_sent:
                auth_logger.error(
                    f"[REGISTRATION EMAIL] [FINAL_RESULT] FAILED for {masked_email}: {email_message}"
                )
                auth_logger.info(
                    f"[REGISTRATION EMAIL] [ACTIVATION_LINK] User {masked_email} activation URL: {verify_url}"
                )
                auth_rate_limiter.record_failure(client_ip, clean_email, action='signup')
                fail_msg = "Your account was created, but we could not send the verification email. Please try again."
                if request.is_json:
                    return jsonify({'success': False, 'error': fail_msg, 'status': 'PENDING_EMAIL_VERIFICATION', 'verification_url': verify_url}), 500
                return render_template('signup.html', error=fail_msg, verification_link=verify_url), 500

            auth_logger.info(f"[REGISTRATION EMAIL] [FINAL_RESULT] SUCCESS for {masked_email}")
            auth_rate_limiter.record_success(client_ip, clean_email, action='signup')

            if request.is_json:
                return jsonify({'success': True, 'message': success_msg, 'status': 'PENDING_VERIFICATION'})
            return render_template('signup.html', success=success_msg)
        except Exception as ex:
            import logging
            logging.getLogger("bullymail.auth").error(f"[SIGNUP ERROR] Account creation exception for {clean_email}: {ex}", exc_info=True)
            auth_rate_limiter.record_failure(client_ip, clean_email, action='signup')
            err_msg = "An error occurred during account creation. Please try again."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg}), 500
            return render_template('signup.html', error=err_msg), 500

    return render_template('signup.html')

# =========================================================================
from functools import wraps

def get_current_user():
    """
    Retrieves fresh user data from DB using session['user_id'].
    Prevents stale role vulnerabilities and immediately blocks disabled/unapproved users.
    Returns user dict or None.
    """
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = UserModel.get_by_id(user_id)
    if not user or user.get('status') != 'ACTIVE':
        return None
    return user

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Unauthorized or account pending approval'}), 401
            session.clear()
            return redirect(url_for('auth.login'))
        return f(user, *args, **kwargs)
    return decorated

def require_platform_owner(f):
    """Restricts endpoint access STRICTLY to the Platform Owner (Jaya Chandra Vennam)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Unauthorized'}), 401
            session.clear()
            return redirect(url_for('auth.login'))
        if user.get('role') != 'platform_owner':
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Forbidden: Platform Owner access required'}), 403
            return render_template('login.html', error="Forbidden: Platform Owner access required."), 403
        return f(user, *args, **kwargs)
    return decorated

def require_role(*roles):
    """
    Role-based access control decorator.
    Supports 'platform_owner', 'org_admin', 'analyst' (and legacy 'admin', 'operator').
    """
    req = set(roles)
    allowed_roles = set(req)

    # Role hierarchy:
    # 1. 'analyst' / 'operator' requirement allows all authenticated roles
    if 'analyst' in req or 'operator' in req:
        allowed_roles.update({'platform_owner', 'org_admin', 'admin', 'analyst', 'operator'})
    # 2. 'org_admin' or 'admin' requirement allows org_admin, admin, and platform_owner
    if 'org_admin' in req or 'admin' in req:
        allowed_roles.update({'platform_owner', 'org_admin', 'admin'})
    # 3. 'platform_owner' requirement strictly allows platform_owner and legacy admin
    if 'platform_owner' in req and 'org_admin' not in req and 'analyst' not in req and 'admin' not in req:
        allowed_roles = {'platform_owner', 'admin'}

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Unauthorized'}), 401
                session.clear()
                return redirect(url_for('auth.login'))
            user_role = user.get('role', 'analyst')
            if user_role not in allowed_roles:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Forbidden: Insufficient privileges'}), 403
                return render_template('login.html', error="Forbidden: Insufficient privileges for this action."), 403
            return f(user, *args, **kwargs)
        return decorated
    return decorator

# =========================================================================
# 2. EMAIL VERIFICATION
# =========================================================================

@auth_bp.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    client_ip = _get_client_ip()
    token = request.args.get('token') or ((request.get_json() or {}).get('token') if request.is_json else request.form.get('token'))

    if not token:
        msg = "Missing or malformed verification token."
        if request.is_json:
            return jsonify({'success': False, 'error': msg}), 400
        return render_template('login.html', error=msg), 400

    # Rate limit check on verification attempts
    is_locked, retry_after = auth_rate_limiter.is_locked(client_ip, token[:16], action='verify_email')
    if is_locked:
        err_msg = "Too many verification attempts. Please wait before retrying."
        if request.is_json:
            return jsonify({'success': False, 'error': err_msg}), 429
        return render_template('login.html', error=err_msg), 429

    user_id = AuthTokenService.verify_and_consume_email_token(token)
    if not user_id:
        auth_rate_limiter.record_failure(client_ip, token[:16], action='verify_email')
        err_msg = "Verification link is invalid, has expired, or has already been used. Please log in or request a new link."
        if request.is_json:
            return jsonify({'success': False, 'error': err_msg}), 400
        return render_template('login.html', error=err_msg), 400

    # Transition account status from PENDING_EMAIL_VERIFICATION to PENDING_ADMIN_APPROVAL
    UserModel.activate_user_email(user_id)
    auth_rate_limiter.record_success(client_ip, token[:16], action='verify_email')

    success_msg = "Your email has been verified successfully! Your account is now pending administrator approval. You will be notified once activated."
    if request.is_json:
        return jsonify({'success': True, 'message': success_msg, 'status': 'PENDING_ADMIN_APPROVAL'})
    return render_template('login.html', success=success_msg)

@auth_bp.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    """
    Allows operators with unverified accounts to re-request their email verification link.
    Maintains strict anti-enumeration uniformity.
    """
    if request.method == 'GET':
        return render_template('login.html', info="Enter your email to request a new verification link.")

    client_ip = _get_client_ip()
    if request.is_json:
        data = request.get_json() or {}
        email = data.get('email') or ''
    else:
        email = request.form.get('email') or ''

    clean_email = UserModel.normalize_email(email)
    generic_msg = (
        "If an account pending verification exists for this email address, "
        "a new verification link has been dispatched to your inbox."
    )

    if not clean_email or '@' not in clean_email:
        if request.is_json:
            return jsonify({'success': False, 'error': 'A valid email address is required.'}), 400
        return render_template('login.html', error='A valid email address is required.'), 400

    is_locked, retry_after = auth_rate_limiter.is_locked(client_ip, clean_email, action='resend_verification')
    if is_locked:
        err_msg = "Too many verification requests. Please wait before retrying."
        if request.is_json:
            return jsonify({'success': False, 'error': err_msg}), 429
        return render_template('login.html', error=err_msg), 429

    user = UserModel.get_by_email(clean_email)
    import logging
    auth_logger = logging.getLogger("bullymail.auth")
    masked_email = clean_email[:3] + "***@" + clean_email.split('@')[-1] if '@' in clean_email else "***"

    if user and user.get('status') == 'PENDING_EMAIL_VERIFICATION':
        try:
            auth_logger.info(f"[REGISTRATION EMAIL] Resend verification requested for recipient={masked_email}")
            raw_token = AuthTokenService.generate_email_verification_token(user['id'])
            verify_url = auth_email_service.get_verification_url(raw_token)
            is_sent, status_msg = auth_email_service.send_verification_email(clean_email, raw_token, user.get('username') or 'User')
            if is_sent:
                auth_logger.info(f"[REGISTRATION EMAIL] [FINAL_RESULT] SUCCESS: verification re-sent to {masked_email}")
                auth_rate_limiter.record_success(client_ip, clean_email, action='resend_verification')
            else:
                auth_logger.error(f"[REGISTRATION EMAIL] [FINAL_RESULT] FAILED: verification resend failed for {masked_email}: {status_msg}")
                auth_logger.info(f"[REGISTRATION EMAIL] [ACTIVATION_LINK] User {masked_email} activation URL: {verify_url}")
                auth_rate_limiter.record_failure(client_ip, clean_email, action='resend_verification')
        except Exception as e:
            auth_logger.error(f"[REGISTRATION EMAIL] Resend verification exception for {masked_email}: {e}")
            auth_rate_limiter.record_failure(client_ip, clean_email, action='resend_verification')
    else:
        # Simulate work to prevent timing enumeration
        auth_logger.info(f"[REGISTRATION EMAIL] Resend verification requested for non-pending or unrecognised recipient={masked_email} (anti-enumeration simulated)")
        UserModel.hash_password("dummy_password_for_timing")
        auth_rate_limiter.record_failure(client_ip, clean_email, action='resend_verification')

    if request.is_json:
        return jsonify({'success': True, 'message': generic_msg})
    return render_template('login.html', success=generic_msg)

# =========================================================================
# 3. LOGIN & AUTHENTICATION
# =========================================================================

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET' and 'user_id' in session:
        user = get_current_user()
        if user:
            return redirect(url_for('main.dashboard'))
        else:
            session.clear()

    if request.method == 'POST':
        client_ip = _get_client_ip()

        # Support both form data and JSON requests
        if request.is_json:
            data = request.get_json() or {}
            identifier = (data.get('username') or data.get('identifier') or '').strip()
            password = data.get('password') or ''
            captcha_token = data.get('captcha_token') or ''
        else:
            identifier = (request.form.get('username') or request.form.get('identifier') or '').strip()
            password = request.form.get('password') or ''
            captcha_token = request.form.get('captcha_token') or ''

        if not identifier or not password:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Identifier and password are required'}), 400
            return render_template('login.html', error='Identifier and password are required'), 400

        # Check Brute-Force Rate Limiting Lockout
        is_locked, retry_after = auth_rate_limiter.is_locked(client_ip, identifier, action='login')
        if is_locked:
            minutes = max(1, (retry_after + 59) // 60)
            err_msg = f"Too many failed login attempts. Access temporarily restricted. Try again in {minutes} minute(s)."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg, 'retry_after': retry_after}), 429
            return render_template('login.html', error=err_msg), 429

        # Check progressive CAPTCHA requirement
        if CaptchaService.is_enabled() or auth_rate_limiter.requires_captcha(client_ip, identifier, action='login'):
            valid_cap, cap_err = CaptchaService.verify_token(captcha_token, client_ip)
            if not valid_cap:
                auth_rate_limiter.record_failure(client_ip, identifier, action='login')
                if request.is_json:
                    return jsonify({'success': False, 'error': cap_err}), 400
                return render_template('login.html', error=cap_err), 400

        user, auth_status = UserModel.authenticate(identifier, password)

        if auth_status == 'SUCCESS' and user:
            # Authentication succeeded: reset rate limit failure counters
            auth_rate_limiter.record_success(client_ip, identifier, action='login')

            # Session Rotation & Fixation Protection
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user.get('full_name') or user.get('username')
            session['role'] = user.get('role', 'analyst')
            session['institution_id'] = user.get('institution_id')
            session['auth_time'] = time.time()
            session.permanent = True

            if request.is_json:
                return jsonify({'success': True, 'message': 'Login successful', 'redirect': url_for('main.dashboard')})
            return redirect(url_for('main.dashboard'))

        elif auth_status == 'PENDING_VERIFICATION':
            auth_rate_limiter.record_failure(client_ip, identifier, action='login')
            err_msg = "Account verification is pending. Please verify your email before logging in."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg, 'status': 'PENDING_VERIFICATION'}), 403
            return render_template('login.html', error=err_msg), 403

        elif auth_status == 'PENDING_ADMIN_APPROVAL':
            auth_rate_limiter.record_failure(client_ip, identifier, action='login')
            err_msg = "Your email has been verified, but your account is pending administrator approval."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg, 'status': 'PENDING_ADMIN_APPROVAL'}), 403
            return render_template('login.html', error=err_msg), 403

        elif auth_status == 'ACCOUNT_LOCKED':
            auth_rate_limiter.record_failure(client_ip, identifier, action='login')
            err_msg = "This account is temporarily locked for security. Please contact your administrator."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg, 'status': 'LOCKED'}), 403
            return render_template('login.html', error=err_msg), 403

        elif auth_status in ('ACCOUNT_DISABLED', 'DISABLED'):
            auth_rate_limiter.record_failure(client_ip, identifier, action='login')
            err_msg = "This account has been disabled. Please contact your administrator."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg, 'status': 'DISABLED'}), 403
            return render_template('login.html', error=err_msg), 403

        else:
            # Generic Invalid Credentials Failure (Anti-Enumeration)
            auth_rate_limiter.record_failure(client_ip, identifier, action='login')

            # Check if this failure triggered a lockout
            is_locked_now, retry_after_now = auth_rate_limiter.is_locked(client_ip, identifier, action='login')
            if is_locked_now:
                minutes = max(1, (retry_after_now + 59) // 60)
                err_msg = f"Too many failed login attempts. Access temporarily restricted for {minutes} minute(s)."
                if request.is_json:
                    return jsonify({'success': False, 'error': err_msg, 'retry_after': retry_after_now}), 429
                return render_template('login.html', error=err_msg), 429

            if request.is_json:
                return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
            return render_template('login.html', error='Invalid username or password'), 401

    return render_template('login.html')

# =========================================================================
# 4. FORGOT PASSWORD
# =========================================================================

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        client_ip = _get_client_ip()

        if request.is_json:
            data = request.get_json() or {}
            email = (data.get('email') or '').strip()
            captcha_token = data.get('captcha_token') or ''
        else:
            email = (request.form.get('email') or '').strip()
            captcha_token = request.form.get('captcha_token') or ''

        # Rate Limiting Check
        is_locked, retry_after = auth_rate_limiter.is_locked(client_ip, email, action='forgot_password')
        if is_locked:
            minutes = max(1, (retry_after + 59) // 60)
            err_msg = f"Too many password reset requests. Please try again in {minutes} minute(s)."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg, 'retry_after': retry_after}), 429
            return render_template('forgot_password.html', error=err_msg), 429

        # CAPTCHA validation
        if CaptchaService.is_enabled() or auth_rate_limiter.requires_captcha(client_ip, email, action='forgot_password'):
            valid_cap, cap_err = CaptchaService.verify_token(captcha_token, client_ip)
            if not valid_cap:
                auth_rate_limiter.record_failure(client_ip, email, action='forgot_password')
                if request.is_json:
                    return jsonify({'success': False, 'error': cap_err}), 400
                return render_template('forgot_password.html', error=cap_err), 400

        # Anti-Enumeration Uniform Response
        uniform_msg = (
            "If an account exists with this email address, password reset instructions have been dispatched. "
            "Please check your inbox."
        )

        clean_email = UserModel.normalize_email(email)
        user = UserModel.get_by_email(clean_email) if clean_email else None

        if user and user.get('status') in ('ACTIVE', 'PENDING_EMAIL_VERIFICATION'):
            raw_token = AuthTokenService.generate_password_reset_token(user['id'])
            auth_email_service.send_password_reset_email(clean_email, raw_token, user.get('username', 'User'))
            auth_rate_limiter.record_success(client_ip, clean_email, action='forgot_password')
        else:
            # Perform dummy work to prevent timing enumeration
            UserModel.hash_password("dummy_password_timing_equalization")
            auth_rate_limiter.record_failure(client_ip, clean_email, action='forgot_password')

        if request.is_json:
            return jsonify({'success': True, 'message': uniform_msg})
        return render_template('forgot_password.html', success=uniform_msg)

    return render_template('forgot_password.html')

# =========================================================================
# 5. PASSWORD RESET
# =========================================================================

@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token') or ((request.get_json() or {}).get('token') if request.is_json else request.form.get('token'))
    client_ip = _get_client_ip()

    if request.method == 'POST':
        if request.is_json:
            data = request.get_json() or {}
            new_password = data.get('password') or ''
            confirm_password = data.get('confirm_password') or ''
            token = data.get('token') or token
        else:
            new_password = request.form.get('password') or ''
            confirm_password = request.form.get('confirm_password') or ''
            token = request.form.get('token') or token

        if not token:
            msg = "Missing or invalid password reset token."
            if request.is_json:
                return jsonify({'success': False, 'error': msg}), 400
            return render_template('reset_password.html', error=msg, token=token), 400

        # Rate Limit Check
        is_locked, retry_after = auth_rate_limiter.is_locked(client_ip, token[:16], action='reset_password')
        if is_locked:
            err_msg = "Too many reset attempts. Please wait before retrying."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg}), 429
            return render_template('reset_password.html', error=err_msg, token=token), 429

        is_match, match_err = UserModel.validate_password_confirmation(new_password, confirm_password)
        if not is_match:
            if request.is_json:
                return jsonify({'success': False, 'error': match_err}), 400
            return render_template('reset_password.html', error=match_err, token=token), 400

        is_valid_pw, pw_err = UserModel.validate_password_policy(new_password)
        if not is_valid_pw:
            if request.is_json:
                return jsonify({'success': False, 'error': pw_err}), 400
            return render_template('reset_password.html', error=pw_err, token=token), 400

        # Atomically validate and consume token
        user_id = AuthTokenService.verify_and_consume_password_reset_token(token)
        if not user_id:
            auth_rate_limiter.record_failure(client_ip, token[:16], action='reset_password')
            err_msg = "This password reset token is invalid, has expired, or has already been used."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg}), 400
            return render_template('reset_password.html', error=err_msg, token=token), 400

        # Update password & invalidate all other outstanding tokens
        UserModel.set_password(user_id, new_password)
        AuthTokenService.invalidate_all_tokens(user_id)

        # Invalidate active session to force re-authentication
        session.clear()
        auth_rate_limiter.record_success(client_ip, token[:16], action='reset_password')

        success_msg = "Password successfully reset! You may now authenticate with your new credentials."
        if request.is_json:
            return jsonify({'success': True, 'message': success_msg})
        return render_template('login.html', success=success_msg)

    return render_template('reset_password.html', token=token)

# =========================================================================
# 6. SESSION MANAGEMENT & LOGOUT
# =========================================================================

@auth_bp.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('main.index')))
    # Ensure session cookies are cleared
    resp.delete_cookie('session')
    return resp

@auth_bp.route('/api/auth/status')
def auth_status():
    user = get_current_user()
    if user:
        return jsonify({
            'authenticated': True,
            'user_id': user.get('id'),
            'username': user.get('username'),
            'full_name': user.get('full_name') or user.get('username'),
            'role': user.get('role'),
            'institution_id': user.get('institution_id')
        })
    return jsonify({'authenticated': False})

# =========================================================================
# 7. ADMINISTRATOR USER APPROVAL & MANAGEMENT (PLATFORM OWNER ONLY)
# =========================================================================

@auth_bp.route('/api/admin/pending-users', methods=['GET'])
@require_role('platform_owner')
def get_pending_users(current_user):
    """Lists accounts awaiting administrator approval (Platform Owner Only)."""
    pending = UserModel.get_pending_approval_users()
    return jsonify({'success': True, 'pending_users': pending})

@auth_bp.route('/api/admin/approve-user/<int:target_user_id>', methods=['POST'])
@require_role('platform_owner')
def approve_user(current_user, target_user_id):
    """Approves a user account, setting status to ACTIVE (Platform Owner Only)."""
    data = request.get_json() or {}
    role = data.get('role', 'org_admin')
    institution_id = data.get('institution_id')

    success = UserModel.approve_user_by_admin(target_user_id, role=role, institution_id=institution_id)
    if not success:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    return jsonify({'success': True, 'message': 'User account approved successfully'})
