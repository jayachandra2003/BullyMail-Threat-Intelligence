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

    if user.get('institution_id') and not session.get('institution_name'):
        from ..models.institution import InstitutionModel
        inst = InstitutionModel.get_by_id(user['institution_id'])
        if inst:
            session['institution_name'] = inst.get('name')

    return render_template('dashboard.html')

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

