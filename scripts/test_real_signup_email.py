#!/usr/bin/env python3
"""
BullyMail V2 - Real SMTP Integration Verification Script
Safely tests transactional email delivery to an actual recipient using .env configuration.
Zero credential leakage: passwords and sensitive tokens are masked.
"""
import os
import sys
import secrets
from pathlib import Path

# Ensure project root is in Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Load .env
try:
    from dotenv import load_dotenv
    env_file = PROJECT_ROOT / '.env'
    if env_file.exists():
        load_dotenv(dotenv_path=env_file)
except ImportError:
    pass

from bullymail import create_app
from bullymail.config import Config
from bullymail.services.auth_email_service import auth_email_service

def mask_email(email_str: str) -> str:
    if not email_str or '@' not in email_str:
        return "***"
    parts = email_str.split('@')
    prefix = parts[0][:3] + "***" if len(parts[0]) > 3 else "***"
    return f"{prefix}@{parts[1]}"

def run_real_signup_email_test(target_email: str = None):
    print("==================================================================")
    print("      🛡️  BullyMail V2 Real SMTP Verification Test Tool         ")
    print("==================================================================")

    # Initialize Flask app to establish configuration context
    app = create_app(Config)

    with app.app_context():
        # Resolve active credentials
        email_addr, app_pw, smtp_h, smtp_p, _ = auth_email_service.email_service._get_credentials()
        base_url = auth_email_service.get_base_url()

        if not target_email:
            target_email = email_addr

        if not target_email or not app_pw:
            print("❌ ERROR: Email integration is not configured in .env.")
            print("   Please ensure EMAIL_ADDRESS and EMAIL_APP_PASSWORD are set.")
            return False

        masked_target = mask_email(target_email)
        masked_sender = mask_email(email_addr)

        print("📋 Safe Configuration Status:")
        print(f" - Sender Account:          {masked_sender}")
        print(f" - Recipient Address:       {masked_target}")
        print(f" - EMAIL_ADDRESS Configured: {bool(email_addr)}")
        print(f" - APP_PASSWORD Configured:  {bool(app_pw)} (Secret masked)")
        print(f" - SMTP Server:             {smtp_h}:{smtp_p}")
        print(f" - APP_BASE_URL:            {base_url}")
        print("------------------------------------------------------------------")

        # Generate a test verification token
        test_token = secrets.token_urlsafe(32)
        verify_url = auth_email_service.get_verification_url(test_token)
        print(f"🔗 Verification URL Template: {verify_url.split('token=')[0]}token=[MASKED]")
        print("🚀 Dispatching real SMTP verification email...")

        # Send email
        is_sent, status_msg = auth_email_service.send_verification_email(
            recipient_email=target_email,
            raw_token=test_token,
            username="TestUser"
        )

        print("------------------------------------------------------------------")
        if is_sent:
            print("✅ SUCCESS: Verification email accepted by SMTP server!")
            print(f"   SMTP Response: {status_msg}")
            print(f"   Check inbox (or Spam folder) for {masked_target}.")
            print("==================================================================")
            return True
        else:
            print("❌ FAILURE: Verification email delivery failed.")
            print(f"   Status Message: {status_msg}")
            print("==================================================================")
            return False

if __name__ == '__main__':
    recipient = sys.argv[1] if len(sys.argv) > 1 else None
    success = run_real_signup_email_test(recipient)
    sys.exit(0 if success else 1)
