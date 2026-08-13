import time
from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, make_response
from ..models.user import UserModel
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
            email = (data.get('email') or '').strip()
            password = data.get('password') or ''
            confirm_password = data.get('confirm_password') or ''
            captcha_token = data.get('captcha_token') or ''
        else:
            username = (request.form.get('username') or '').strip()
            email = (request.form.get('email') or '').strip()
            password = request.form.get('password') or ''
            confirm_password = request.form.get('confirm_password') or ''
            captcha_token = request.form.get('captcha_token') or ''

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
            # Simulate work to prevent timing enumeration
            UserModel.hash_password(password)
            auth_rate_limiter.record_failure(client_ip, clean_email, action='signup')
            if request.is_json:
                return jsonify({'success': True, 'message': success_msg, 'status': 'PENDING_VERIFICATION'})
            return render_template('signup.html', success=success_msg)

        try:
            user_id = UserModel.create_user(
                username=username,
                password=password,
                email=clean_email,
                role='analyst',
                status='PENDING_EMAIL_VERIFICATION'
            )

            # Generate single-use verification token
            raw_token = AuthTokenService.generate_email_verification_token(user_id)
            auth_email_service.send_verification_email(clean_email, raw_token, username)
            auth_rate_limiter.record_success(client_ip, clean_email, action='signup')

            if request.is_json:
                return jsonify({'success': True, 'message': success_msg, 'status': 'PENDING_VERIFICATION'})
            return render_template('signup.html', success=success_msg)
        except Exception:
            auth_rate_limiter.record_failure(client_ip, clean_email, action='signup')
            err_msg = "An error occurred during account creation. Please try again."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg}), 500
            return render_template('signup.html', error=err_msg), 500

    return render_template('signup.html')

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

    # Activate account
    UserModel.activate_user_email(user_id)
    auth_rate_limiter.record_success(client_ip, token[:16], action='verify_email')

    success_msg = "Your email has been verified successfully! You may now authenticate."
    if request.is_json:
        return jsonify({'success': True, 'message': success_msg})
    return render_template('login.html', success=success_msg)

# =========================================================================
# 3. LOGIN & AUTHENTICATION
# =========================================================================

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET' and 'user_id' in session:
        return redirect(url_for('main.dashboard'))

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
            session['role'] = user.get('role', 'analyst')
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

        elif auth_status == 'ACCOUNT_LOCKED':
            auth_rate_limiter.record_failure(client_ip, identifier, action='login')
            err_msg = "This account is temporarily locked for security. Please contact your administrator."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg, 'status': 'LOCKED'}), 403
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
    if 'user_id' in session:
        return jsonify({
            'authenticated': True,
            'user_id': session.get('user_id'),
            'username': session.get('username'),
            'role': session.get('role')
        })
    return jsonify({'authenticated': False})
