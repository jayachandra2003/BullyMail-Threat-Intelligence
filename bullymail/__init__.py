import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from .config import Config
from .database.connection import init_db

def create_app(config_class=Config):
    """BullyMail V2 Application Factory with Global Security Middleware"""
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), '..', 'templates'),
        static_folder=os.path.join(os.path.dirname(__file__), '..', 'static')
    )
    
    app.config.from_object(config_class)
    
    # Enforce explicit SECRET_KEY in production mode
    if app.config.get('FLASK_ENV') == 'production' and not app.config.get('SECRET_KEY'):
        raise ValueError("CRITICAL SECURITY CONFIGURATION ERROR: SECRET_KEY must be explicitly defined in environment for production deployments.")
    
    # Configure CORS
    CORS(app, supports_credentials=True)
    
    # Ensure storage directories exist
    os.makedirs(app.config['MODEL_PATH'], exist_ok=True)
    os.makedirs(app.config['DATASET_PATH'], exist_ok=True)
    os.makedirs(app.config['UPLOAD_PATH'], exist_ok=True)
    
    # Register Blueprints
    from .routes.main import main_bp
    from .routes.auth import auth_bp
    from .routes.analysis import analysis_bp
    from .routes.models import models_bp
    from .routes.datasets import datasets_bp
    from .routes.email_integration import email_bp
    from .routes.reports import reports_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(models_bp)
    app.register_blueprint(datasets_bp)
    app.register_blueprint(email_bp)
    app.register_blueprint(reports_bp)
    
    # Initialize Database Schema
    try:
        init_db()
    except Exception as e:
        # Avoid printing internal exception trace in logs
        print(f"[BullyMail Schema Setup] Notification: {type(e).__name__}")

    # =========================================================================
    # Global Security Headers Middleware
    # =========================================================================
    @app.after_request
    def set_security_headers(response):
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Prevent Clickjacking / Framing
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Legacy browser XSS filter
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Hardware Permissions Policy
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        
        # HTTP Strict Transport Security (HSTS) - Enforced when over HTTPS or in production
        is_prod = app.config.get('FLASK_ENV') == 'production'
        if is_prod or request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
        # Tailored Content Security Policy (CSP) compatible with Chart.js, CDNs, & Google Fonts
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
            "img-src 'self' data: blob:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ]
        response.headers['Content-Security-Policy'] = "; ".join(csp_directives)
        
        return response

    # =========================================================================
    # Safe Global Error Handlers (Zero Leakage)
    # =========================================================================
    @app.errorhandler(400)
    def bad_request(e):
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'success': False, 'error': 'Bad request or malformed payload'}), 400
        return "Bad Request", 400

    @app.errorhandler(401)
    def unauthorized(e):
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'success': False, 'error': 'Unauthorized access'}), 401
        return "Unauthorized", 401

    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'success': False, 'error': 'Forbidden access'}), 403
        return "Forbidden", 403

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'success': False, 'error': 'Endpoint or resource not found'}), 404
        return "Resource Not Found", 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'success': False, 'error': 'Method not allowed for this endpoint'}), 405
        return "Method Not Allowed", 405

    @app.errorhandler(429)
    def rate_limited(e):
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'success': False, 'error': 'Too many requests. Rate limit exceeded.'}), 429
        return "Too Many Requests", 429

    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'success': False, 'error': 'An internal security exception occurred.'}), 500
        return "Internal Server Error", 500

    return app
