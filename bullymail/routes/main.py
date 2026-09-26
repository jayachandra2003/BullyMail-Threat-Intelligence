import os
from flask import Blueprint, render_template, session, redirect, url_for, send_from_directory, current_app, jsonify

from .auth import get_current_user

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))

    from .auth import normalize_role
    user_role = normalize_role(user.get('role'))
    session['role'] = user_role
    session['institution_id'] = user.get('institution_id')
    session['username'] = user.get('username')
    session['full_name'] = user.get('full_name') or user.get('username')

    inst_name = None
    if user.get('institution_id'):
        from ..models.institution import InstitutionModel
        inst = InstitutionModel.get_by_id(user['institution_id'])
        if inst:
            inst_name = inst.get('name')
            session['institution_name'] = inst_name
        else:
            session.pop('institution_name', None)
    else:
        session.pop('institution_name', None)

    is_platform_owner = (user_role == 'platform_owner')
    is_org_admin = (user_role == 'org_admin') or (user_role == 'admin' and user.get('institution_id'))
    is_analyst = not is_platform_owner and not is_org_admin

    return render_template(
        'dashboard.html',
        current_user=user,
        current_role=user_role,
        is_platform_owner=is_platform_owner,
        is_org_admin=is_org_admin,
        is_analyst=is_analyst,
        institution_name=inst_name
    )

@main_bp.route('/login')
def login():
    user = get_current_user()
    if user:
        return redirect(url_for('main.dashboard'))
    return render_template('login.html')

@main_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.index'))

@main_bp.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(current_app.root_path, '..', 'static'),
        'favicon.svg',
        mimetype='image/svg+xml'
    )

@main_bp.route('/robots.txt')
def robots():
    return send_from_directory(
        os.path.join(current_app.root_path, '..', 'static'),
        'robots.txt',
        mimetype='text/plain'
    )

@main_bp.route('/sitemap.xml')
def sitemap():
    return send_from_directory(
        os.path.join(current_app.root_path, '..', 'static'),
        'sitemap.xml',
        mimetype='application/xml'
    )

@main_bp.route('/privacy')
def privacy():
    return render_template('privacy.html')

@main_bp.route('/terms')
def terms():
    return render_template('terms.html')

@main_bp.route('/health')
def health():
    """Lightweight zero-overhead health check endpoint for cloud platform probes (e.g., Render)."""
    return jsonify({'status': 'ok', 'service': 'BullyMail Threat Intelligence Platform'}), 200

