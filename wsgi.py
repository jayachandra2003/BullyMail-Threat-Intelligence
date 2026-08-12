"""
BullyMail V2 - Production WSGI Application Entrypoint
"""
import os
from bullymail import create_app
from bullymail.config import Config

# Enforce production security defaults for standalone WSGI runtime
Config.DEBUG = False

app = create_app(Config)
application = app

if __name__ == '__main__':
    from waitress import serve
    host = os.environ.get('HOST', Config.HOST)
    port = int(os.environ.get('PORT', Config.PORT))
    print(f"[*] Starting BullyMail V2 Production WSGI Server (Waitress) on http://{host}:{port}")
    serve(app, host=host, port=port)
