import html
from ..config import Config
from .email_service import EmailService

class AuthEmailService:
    """
    Service for sending transactional authentication emails
    (Email Verification, Password Reset) with trusted base URLs and no credential leakage.
    """

    def __init__(self):
        self.email_service = EmailService()

    @classmethod
    def get_base_url(cls) -> str:
        """Resolves trusted application base URL from active Flask app context, live request, or Config."""
        try:
            from flask import current_app, request, has_request_context
            if current_app and current_app.config.get('APP_BASE_URL'):
                configured = current_app.config.get('APP_BASE_URL').rstrip('/')
                # If explicitly configured to an external URL or custom port (not default localhost), prioritize it
                if configured and configured != 'http://localhost:5000':
                    return configured
                # If configured as localhost default but we are handling a live web request (e.g. on Render), prefer public request host
                if has_request_context() and request and request.host_url:
                    proto = request.headers.get('X-Forwarded-Proto')
                    if proto:
                        return f"{proto}://{request.host}".rstrip('/')
                    return request.host_url.rstrip('/')
                return configured

            if has_request_context() and request and request.host_url:
                proto = request.headers.get('X-Forwarded-Proto')
                if proto:
                    return f"{proto}://{request.host}".rstrip('/')
                return request.host_url.rstrip('/')
        except Exception:
            pass
        return (getattr(Config, 'APP_BASE_URL', None) or 'http://localhost:5000').rstrip('/')

    def get_verification_url(self, raw_token: str) -> str:
        """Constructs canonical email verification URL."""
        base_url = self.get_base_url()
        return f"{base_url}/verify-email?token={raw_token}"

    def get_password_reset_url(self, raw_token: str) -> str:
        """Constructs canonical password reset URL."""
        base_url = self.get_base_url()
        return f"{base_url}/reset-password?token={raw_token}"

    def send_verification_email(self, recipient_email: str, raw_token: str, username: str = "User") -> tuple[bool, str]:
        """
        Dispatches account verification link with trusted base URL and single-use token.
        Returns:
            tuple[bool, str]: (is_sent, status_message)
        """
        verify_url = self.get_verification_url(raw_token)

        subject = "Action Required: Verify Your BullyMail Account"
        body = (
            f"Hello {username},\n\n"
            f"Thank you for registering for the BullyMail Threat Intelligence Platform.\n\n"
            f"Please verify your email address to activate your account by clicking the link below:\n"
            f"{verify_url}\n\n"
            f"This single-use link will expire in {Config.AUTH_EMAIL_TOKEN_EXPIRY_HOURS} hours.\n"
            f"If you did not request this registration, no further action is required.\n\n"
            f"— BullyMail Security Team"
        )

        escaped_user = html.escape(username or 'User')
        html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f8fafc; margin: 0; padding: 20px; }}
.card {{ max-width: 580px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 32px; }}
.header {{ font-size: 20px; font-weight: 700; color: #0f172a; margin-bottom: 20px; border-bottom: 2px solid #3b82f6; padding-bottom: 12px; }}
.btn {{ display: inline-block; background-color: #2563eb; color: #ffffff !important; font-weight: 600; text-decoration: none; padding: 12px 24px; border-radius: 6px; margin: 20px 0; font-size: 15px; }}
.footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b; }}
.token-note {{ font-size: 13px; color: #64748b; margin-top: 10px; }}
</style>
</head>
<body>
<div class="card">
<div class="header">🛡️ Verify Your BullyMail Account</div>
<p>Hello <strong>{escaped_user}</strong>,</p>
<p>Thank you for registering for the <strong>BullyMail Threat Intelligence Platform</strong>.</p>
<p>Please click the button below to verify your email address and activate your account access:</p>
<p style="text-align: center;">
<a href="{verify_url}" class="btn" style="color: #ffffff;">Verify Email Address</a>
</p>
<p class="token-note">If the button does not work, copy and paste this link into your browser:<br>
<a href="{verify_url}" style="color: #2563eb; word-break: break-all;">{verify_url}</a></p>
<p class="token-note">This link will expire in {Config.AUTH_EMAIL_TOKEN_EXPIRY_HOURS} hours. If you did not create this account, no action is needed.</p>
<div class="footer">BullyMail Threat Intelligence Platform • Security Operations</div>
</div>
</body>
</html>"""

        return self.email_service.send_email(recipient_email, subject, body, html_body=html_body)

    def send_password_reset_email(self, recipient_email: str, raw_token: str, username: str = "User") -> tuple[bool, str]:
        """
        Dispatches password reset link with trusted base URL and single-use token.
        Returns:
            tuple[bool, str]: (is_sent, status_message)
        """
        reset_url = self.get_password_reset_url(raw_token)

        subject = "BullyMail Security Alert: Password Reset Request"
        body = (
            f"Hello {username},\n\n"
            f"A password reset request was submitted for your BullyMail account.\n\n"
            f"To choose a new password, click the link below or paste it into your browser:\n"
            f"{reset_url}\n\n"
            f"This link is valid for {Config.AUTH_RESET_TOKEN_EXPIRY_MINUTES} minutes and can only be used once.\n"
            f"If you did not request a password reset, please ignore this message. Your password will remain unchanged.\n\n"
            f"— BullyMail Security Team"
        )

        escaped_user = html.escape(username or 'User')
        html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f8fafc; margin: 0; padding: 20px; }}
.card {{ max-width: 580px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 32px; }}
.header {{ font-size: 20px; font-weight: 700; color: #0f172a; margin-bottom: 20px; border-bottom: 2px solid #ef4444; padding-bottom: 12px; }}
.btn {{ display: inline-block; background-color: #ef4444; color: #ffffff !important; font-weight: 600; text-decoration: none; padding: 12px 24px; border-radius: 6px; margin: 20px 0; font-size: 15px; }}
.footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b; }}
.token-note {{ font-size: 13px; color: #64748b; margin-top: 10px; }}
</style>
</head>
<body>
<div class="card">
<div class="header">🛡️ Password Reset Request</div>
<p>Hello <strong>{escaped_user}</strong>,</p>
<p>A password reset request was submitted for your <strong>BullyMail</strong> account.</p>
<p>To choose a new password, click the button below:</p>
<p style="text-align: center;">
<a href="{reset_url}" class="btn" style="color: #ffffff;">Reset Password</a>
</p>
<p class="token-note">If the button does not work, copy and paste this link into your browser:<br>
<a href="{reset_url}" style="color: #2563eb; word-break: break-all;">{reset_url}</a></p>
<p class="token-note">This link is valid for {Config.AUTH_RESET_TOKEN_EXPIRY_MINUTES} minutes and can only be used once.</p>
<p class="token-note">If you did not request a password reset, please ignore this message. Your password will remain unchanged.</p>
<div class="footer">BullyMail Threat Intelligence Platform • Security Operations</div>
</div>
</body>
</html>"""

        return self.email_service.send_email(recipient_email, subject, body, html_body=html_body)

auth_email_service = AuthEmailService()
