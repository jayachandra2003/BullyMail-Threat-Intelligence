import re
import math

class PhishingDetector:
    """Dedicated Phishing & Credential Theft Detection Engine"""
    
    # 1. Credential Harvesting Patterns
    CREDENTIAL_PATTERNS = [
        (r'\b(verify|confirm|validate|update|reset|re-activate|authenticate)\s+(your\s+)?(password|account|credentials|pin|login|id|security\s+settings|passcode)\b', 'Credential Verification Request', 'CRITICAL', 0.40),
        (r'\b(click\s+here\s+to\s+(log\s*in|sign\s*in|authenticate|unlock|verify|update))\b', 'Direct Login/Auth Call-To-Action', 'HIGH', 0.35),
        (r'\b(enter|provide|submit)\s+(your\s+)?(username|password|ssn|social\s+security|credit\s+card|bank\s+account|credentials)\b', 'Direct Request for Sensitive Credentials', 'CRITICAL', 0.45),
        (r'\b(student\s+portal\s+verification|webmail\s+portal\s+access|sign-in\s+portal)\b', 'Portal Verification Pretext', 'HIGH', 0.30)
    ]
    
    # 2. Account Alert & Security Pretext Patterns
    ACCOUNT_ALERT_PATTERNS = [
        (r'\b(unusual|unauthorized|suspicious|unrecognized)\s+(activity|sign-in|login|access|attempt|location|device)(\s+(detected|noticed|observed|found))?\b', 'Security Alert / Suspicious Activity Pretext', 'HIGH', 0.35),
        (r'\b(account\s+(has\s+been\s+)?(locked|suspended|restricted|disabled|compromised|flagged|temporarily\s+blocked))\b', 'Account Suspension / Lockout Pretext', 'HIGH', 0.35),
        (r'\b(security\s+(alert|warning|notice|compromise)|account\s+security\s+alert)\b', 'Urgent Security Pretext', 'MEDIUM', 0.25)
    ]
    
    # 3. Urgency & Time Pressure Patterns
    URGENCY_PATTERNS = [
        (r'\b(within\s+(24|48|12|1|2|3|4|6|8)\s*(hours?|hrs?|days?))\b', 'Time Limit Window Pressure', 'HIGH', 0.30),
        (r'\b(immediate(ly)?\s+action\s+required|act\s+now|urgent\s+attention|immediate\s+response|without\s+delay)\b', 'Urgency Callout', 'HIGH', 0.25),
        (r'\b(immediate(ly)?|urgent(ly)?)\b', 'Urgency Qualifier', 'MEDIUM', 0.15)
    ]
    
    # 4. Threat of Consequence / Deactivation Patterns
    CONSEQUENCE_PATTERNS = [
        (r'\b((or\s+)?(your\s+)?account\s+will\s+be\s+(permanently\s+)?(deleted|deactivated|suspended|terminated|closed|locked|disabled))\b', 'Account Deletion / Termination Threat', 'CRITICAL', 0.40),
        (r'\b(to\s+prevent\s+(permanent\s+)?(account\s+)?(deactivation|deletion|suspension|termination|closure|lockout))\b', 'Prevent Deactivation Pretext', 'CRITICAL', 0.40),
        (r'\b(failure\s+to\s+comply(\s+will\s+result\s+in)?|permanent\s+loss\s+of\s+access)\b', 'Consequence / Penalty Threat', 'HIGH', 0.30)
    ]
    
    # 5. Financial Extortion & Advance Fee Scam Patterns
    FINANCIAL_PATTERNS = [
        (r'\b(wire\s+transfer|bitcoin|crypto|gift\s+cards?|itunes\s+card|steam\s+card|direct\s+deposit)\b', 'High-Risk Payment Request', 'CRITICAL', 0.40),
        (r'\b(invoice\s+(attached|overdue|payment|enclosed)|outstanding\s+balance|remittance\s+advice)\b', 'Invoice/Financial Pretext', 'MEDIUM', 0.20),
        (r'\b(claim\s+your\s+(reward|prize|grant|funds|lottery|payout|settlement))\b', 'Financial Lure / Advance Fee Scam', 'HIGH', 0.35)
    ]
    
    # 6. Authority & IT Spoofing Patterns
    SPOOFING_PATTERNS = [
        (r'\b(it\s+support\s+desk|helpdesk\s+admin|system\s+administrator|office\s+365\s+team|google\s+security\s+team|it\s+helpdesk)\b', 'Authority / Technical Support Impersonation', 'HIGH', 0.25),
        (r'\b(payroll\s+department|human\s+resources|hr\s+director|finance\s+department)\b', 'Internal Corporate Impersonation', 'MEDIUM', 0.20)
    ]

    # 7. Mitigating Context Patterns for Legitimate Informational Notifications
    MITIGATING_ALERT_PATTERNS = [
        r'\b(no\s+action\s+is\s+(needed|required|necessary))\b',
        r'\b(if\s+this\s+was\s+you|if\s+you\s+recognize\s+this(\s+activity)?)\b',
        r'\b(you\s+can\s+(safely\s+)?ignore\s+this(\s+message|\s+email|\s+notification)?)\b',
        r'\b(this\s+is\s+(just\s+|only\s+)?an?\s+informational\s+(notice|alert|message))\b',
        r'\b(this\s+was\s+you)\b'
    ]

    def analyze(self, email_text, email_subject="", email_from="", urls_detected=None):
        """Analyzes an email for phishing vectors using multi-indicator synergy scoring."""
        if not email_text and not email_subject:
            return {
                'risk_level': 'LOW',
                'confidence': 0.0,
                'threat_score': 0.0,
                'indicators': [],
                'explanation': 'No email content provided.'
            }
            
        full_content = f"{email_subject} {email_text}".lower()
        indicators = []
        raw_score = 0.0
        
        has_credential_intent = False
        has_account_alert = False
        has_urgency = False
        has_consequence_threat = False
        
        # 1. Scan Credential Harvesting Vectors
        for pat, title, severity, weight in self.CREDENTIAL_PATTERNS:
            matches = re.findall(pat, full_content)
            if matches:
                has_credential_intent = True
                raw_score += weight
                indicators.append({
                    'category': 'Credential Harvesting',
                    'title': title,
                    'severity': severity,
                    'description': f"Email requests authentication or credential verification: '{matches[0][0] if isinstance(matches[0], tuple) else matches[0]}'"
                })
                break  # Deduplicate within category
                
        # 2. Scan Account Alert / Lockout Pretexts
        for pat, title, severity, weight in self.ACCOUNT_ALERT_PATTERNS:
            matches = re.findall(pat, full_content)
            if matches:
                has_account_alert = True
                raw_score += weight
                indicators.append({
                    'category': 'Account Alert Pretext',
                    'title': title,
                    'severity': severity,
                    'description': f"Email claims security issue or account compromise: '{matches[0][0] if isinstance(matches[0], tuple) else matches[0]}'"
                })
                break
                
        # 3. Scan Urgency & Deadlines
        for pat, title, severity, weight in self.URGENCY_PATTERNS:
            matches = re.findall(pat, full_content)
            if matches:
                has_urgency = True
                raw_score += weight
                indicators.append({
                    'category': 'Urgency & Pressure',
                    'title': title,
                    'severity': severity,
                    'description': f"Artificial time pressure detected: '{matches[0][0] if isinstance(matches[0], tuple) else matches[0]}'"
                })
                break

        # 4. Scan Threat of Consequence / Deactivation
        for pat, title, severity, weight in self.CONSEQUENCE_PATTERNS:
            matches = re.findall(pat, full_content)
            if matches:
                has_consequence_threat = True
                raw_score += weight
                indicators.append({
                    'category': 'Consequence Threat',
                    'title': title,
                    'severity': severity,
                    'description': f"Threat of account lockout, deactivation, or penalty: '{matches[0][0] if isinstance(matches[0], tuple) else matches[0]}'"
                })
                break

        # 5. Scan Financial Fraud Patterns
        for pat, title, severity, weight in self.FINANCIAL_PATTERNS:
            matches = re.findall(pat, full_content)
            if matches:
                raw_score += weight
                indicators.append({
                    'category': 'Financial Lure',
                    'title': title,
                    'severity': severity,
                    'description': f"Financial transaction or advance fee pretext: '{matches[0][0] if isinstance(matches[0], tuple) else matches[0]}'"
                })
                break
                
        # 6. Scan Authority Pretexts
        for pat, title, severity, weight in self.SPOOFING_PATTERNS:
            matches = re.findall(pat, full_content)
            if matches:
                raw_score += weight
                indicators.append({
                    'category': 'Impersonation Pretext',
                    'title': title,
                    'severity': severity,
                    'description': f"Uses common authority / IT support titles: '{matches[0] if isinstance(matches[0], str) else matches[0][0]}'"
                })
                break

        # 7. Check Sender vs Display Name Mismatch
        if email_from:
            from_lower = email_from.lower()
            if any(b in from_lower for b in ['paypal', 'microsoft', 'google', 'apple', 'admin', 'it support', 'helpdesk', 'it helpdesk', 'security team']):
                if any(f in from_lower for f in ['@gmail.com', '@yahoo.com', '@hotmail.com', '@outlook.com', '@mail.com']):
                    raw_score += 0.35
                    indicators.append({
                        'category': 'Sender Mismatch',
                        'title': 'Display Name & Domain Mismatch',
                        'severity': 'HIGH',
                        'description': f"Sender '{email_from}' claims official brand identity using a free public webmail address."
                    })

        # 8. Correlate with Embedded URLs
        has_suspicious_urls = False
        if urls_detected:
            suspicious_urls = [u for u in urls_detected if u.get('risk_level') in ('SUSPICIOUS', 'HIGH_RISK', 'MALICIOUS')]
            if suspicious_urls:
                has_suspicious_urls = True
                raw_score += 0.30 * len(suspicious_urls)
                indicators.append({
                    'category': 'Suspicious Links',
                    'title': 'Email Contains Risky URLs',
                    'severity': 'HIGH',
                    'description': f"Detected {len(suspicious_urls)} suspicious or high-risk link(s) embedded in email."
                })

        # 9. Multi-Indicator Synergistic Bonus (Combined Phishing Attack Vectors)
        core_indicator_count = sum([has_credential_intent, has_account_alert, has_urgency, has_consequence_threat])
        if has_credential_intent and core_indicator_count >= 3:
            raw_score += 0.40  # Classic 3+ factor phishing attack -> Escalates to CRITICAL/HIGH
        elif has_credential_intent and core_indicator_count >= 2:
            raw_score += 0.25  # 2 factor phishing combo
        elif not has_credential_intent and core_indicator_count == 1 and has_urgency:
            # Single urgency without credential/account pretexts is NOT phishing
            raw_score = min(raw_score, 0.20)

        # 10. Check Informational Mitigating Context (e.g. "If this was you, no action is needed")
        has_mitigating_context = any(bool(re.search(pat, full_content)) for pat in self.MITIGATING_ALERT_PATTERNS)
        if has_mitigating_context and not has_credential_intent and not has_consequence_threat and not has_suspicious_urls:
            raw_score = min(raw_score, 0.15)
            indicators = [ind for ind in indicators if ind.get('category') != 'Account Alert Pretext']

        # Calibrate Confidence
        confidence = round(1.0 - math.exp(-1.8 * raw_score), 3) if raw_score > 0 else 0.0
        
        # Risk classification
        if confidence >= 0.70 or (has_credential_intent and core_indicator_count >= 2):
            risk_level = 'CRITICAL' if confidence >= 0.88 or (has_credential_intent and core_indicator_count >= 3) else 'HIGH'
            confidence = max(confidence, 0.75)
        elif confidence >= 0.35:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
            
        if risk_level == 'LOW':
            explanation = "No significant phishing, credential theft, or social engineering cues detected."
        else:
            reasons = [ind['title'] for ind in indicators[:3]]
            explanation = f"Phishing risk assessed as {risk_level} ({int(confidence*100)}% confidence) due to: {', '.join(reasons)}."
            
        return {
            'risk_level': risk_level,
            'confidence': confidence,
            'threat_score': round(min(raw_score, 1.0), 3),
            'indicators': indicators,
            'explanation': explanation
        }
