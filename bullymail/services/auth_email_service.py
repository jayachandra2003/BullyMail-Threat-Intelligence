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
    def get_base_url(cls):
        return Config.APP_BASE_URL.rstrip('/')

    def send_verification_email(self, recipient_email: str, raw_token: str, username: str = "User") -> bool:
        """
        Dispatches account verification link with trusted base URL and single-use token.
        """
        base_url = self.get_base_url()
        verify_url = f"{base_url}/verify-email?token={raw_token}"

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

        return self.email_service.send_email(recipient_email, subject, body)

    def send_password_reset_email(self, recipient_email: str, raw_token: str, username: str = "User") -> bool:
        """
        Dispatches password reset link with trusted base URL and single-use token.
        """
        base_url = self.get_base_url()
        reset_url = f"{base_url}/reset-password?token={raw_token}"

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

        return self.email_service.send_email(recipient_email, subject, body)

auth_email_service = AuthEmailService()
