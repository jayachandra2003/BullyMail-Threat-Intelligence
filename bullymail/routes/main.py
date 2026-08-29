import os
from flask import Blueprint, render_template, session, redirect, url_for, send_from_directory, current_app

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
