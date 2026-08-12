import os
from bullymail import create_app
from bullymail.config import Config

app = create_app(Config)

if __name__ == '__main__':
    print("==================================================================")
    print("      🛡️  Starting BullyMail V2 Threat Intelligence Platform     ")
    print("==================================================================")
    print(f"Server running at: http://localhost:{Config.PORT}")
    print(f"Active Storage Path: {Config.MODEL_PATH}")
    print(f"Active Admin User: {Config.ADMIN_USERNAME}")
    print("==================================================================")
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )
