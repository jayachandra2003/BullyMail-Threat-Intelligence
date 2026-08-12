from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template
from ..models.user import UserModel
from ..services.rate_limiter import login_rate_limiter

auth_bp = Blueprint('auth', __name__)

def _get_client_ip():
    """Extracts client IP considering potential proxy forwarding."""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        client_ip = _get_client_ip()
        
        # Support both form data and JSON requests
        if request.is_json:
            data = request.get_json() or {}
            username = (data.get('username') or '').strip()
            password = (data.get('password') or '').strip()
        else:
            username = (request.form.get('username') or '').strip()
            password = (request.form.get('password') or '').strip()

        if not username or not password:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Username and password required'}), 400
            return render_template('login.html', error='Username and password required'), 400

        # Check Brute-Force Rate Limiting Lockout
        is_locked, retry_after = login_rate_limiter.is_locked(client_ip, username)
        if is_locked:
            minutes = max(1, (retry_after + 59) // 60)
            err_msg = f"Too many failed login attempts. Access temporarily restricted. Try again in {minutes} minute(s)."
            if request.is_json:
                return jsonify({
                    'success': False,
                    'error': err_msg,
                    'retry_after': retry_after
                }), 429
            return render_template('login.html', error=err_msg), 429

        user = UserModel.authenticate(username, password)
        if user:
            # Authentication succeeded: reset rate limit failure counter
            login_rate_limiter.record_success(client_ip, username)
            
            # Prevent session fixation
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user.get('role', 'admin')
            session.permanent = True
            
            if request.is_json:
                return jsonify({'success': True, 'message': 'Login successful', 'redirect': url_for('main.dashboard')})
            return redirect(url_for('main.dashboard'))
        else:
            # Authentication failed: increment failure counter
            login_rate_limiter.record_failure(client_ip, username)
            
            # Re-check if this failure triggered a lockout
            is_locked_now, retry_after_now = login_rate_limiter.is_locked(client_ip, username)
            if is_locked_now:
                minutes = max(1, (retry_after_now + 59) // 60)
                err_msg = f"Too many failed login attempts. Access temporarily restricted for {minutes} minute(s)."
                if request.is_json:
                    return jsonify({
                        'success': False,
                        'error': err_msg,
                        'retry_after': retry_after_now
                    }), 429
                return render_template('login.html', error=err_msg), 429

            if request.is_json:
                return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
            return render_template('login.html', error='Invalid username or password'), 401

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.index'))

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
