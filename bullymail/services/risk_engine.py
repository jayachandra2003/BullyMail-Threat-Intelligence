import math
from .bullying_detector import BullyingDetector
from .phishing_detector import PhishingDetector
from .url_analyzer import URLAnalyzer
from .domain_detector import DomainDetector
from .social_engineering import SocialEngineeringDetector
from .malware_analyzer import MalwareAnalyzer
from .image_forensics import ImageForensicsEngine
from .explainable_ai import ExplainableAI

class UnifiedRiskEngine:
    """Central Threat Assessment & Multi-Vector Risk Aggregation Engine with Tiered Severity"""
    
    def __init__(self):
        self.bullying_detector = BullyingDetector()
        self.phishing_detector = PhishingDetector()
        self.url_analyzer = URLAnalyzer()
        self.domain_detector = DomainDetector()
        self.social_detector = SocialEngineeringDetector()
        self.malware_analyzer = MalwareAnalyzer()
        self.image_forensics = ImageForensicsEngine()
        self.xai = ExplainableAI()

    def analyze_email(self, email_text, email_subject="", email_from="", email_to="", attachments=None, images=None):
        """Executes full multi-vector inspection and aggregates into a unified security report."""
        email_text = email_text or ""
        email_subject = email_subject or ""
        email_from = email_from or ""
        
        # 1. Run URL & Link Security Analyzer
        url_results = self.url_analyzer.analyze_all(f"{email_subject} {email_text}")
        
        # 2. Run Look-Alike / Domain Detector on sender and any extracted URLs
        domain_result = self.domain_detector.check_domain(email_from)
        if not domain_result.get('is_suspicious') and url_results.get('urls'):
            for u in url_results['urls']:
                d_res = self.domain_detector.check_domain(u['url'])
                if d_res.get('is_suspicious'):
                    domain_result = d_res
                    break

        # 3. Run Dedicated Phishing Detector
        phishing_result = self.phishing_detector.analyze(
            email_text=email_text,
            email_subject=email_subject,
            email_from=email_from,
            urls_detected=url_results.get('urls', [])
        )
        
        # 4. Run Cyberbullying Detector with Severity Tiers
        bullying_result = self.bullying_detector.predict(email_text)
        
        # 5. Run Social Engineering Detector
        social_result = self.social_detector.analyze(email_text, email_subject)
        
        # 6. Run Safe Static Malware & Attachment Analysis
        malware_result = self.malware_analyzer.analyze_attachments(attachments or [])
        
        # 7. Run Passive Image Forensics
        image_result = self.image_forensics.analyze_images(images or [])

        # 8. Unified Risk Calculation (Documented & Transparent Scoring Strategy)
        b_score = bullying_result.get('confidence', 0.0) if bullying_result.get('is_bullying') else 0.0
        b_severity = bullying_result.get('severity', 'LOW')
        p_score = phishing_result.get('confidence', 0.0) if phishing_result.get('risk_level') != 'LOW' else 0.0
        u_score = 0.85 if url_results.get('overall_risk') == 'HIGH_RISK' else (0.45 if url_results.get('overall_risk') == 'SUSPICIOUS' else 0.0)
        m_score = 0.95 if malware_result.get('risk_level') == 'HIGH_RISK' else (0.45 if malware_result.get('risk_level') == 'SUSPICIOUS' else 0.0)
        s_score = social_result.get('confidence', 0.0) if social_result.get('risk_level') != 'LOW' else 0.0
        i_score = 0.70 if image_result.get('risk_level') == 'HIGH' else (0.35 if image_result.get('risk_level') == 'MEDIUM' else 0.0)
        
        # Weighted composite score
        composite_score = (
            (p_score * 0.30) +
            (b_score * 0.25) +
            (u_score * 0.20) +
            (m_score * 0.15) +
            (s_score * 0.10)
        )
        
        # Critical override: take the maximum of any single high-severity trigger
        peak_score = max(b_score, p_score, u_score, m_score, s_score, i_score)
        
        if domain_result.get('is_suspicious'):
            peak_score = max(peak_score, 0.75)
            
        # Final Threat Score fuses composite and peak
        final_threat_score = round(max(composite_score, peak_score), 3)
        
        # Risk Level Determination (Gated by Severity & Compounding Evidence)
        if b_severity == 'CRITICAL' or final_threat_score >= 0.88 or m_score >= 0.90 or phishing_result.get('risk_level') == 'CRITICAL':
            overall_risk = 'CRITICAL'
        elif b_severity == 'HIGH' or final_threat_score >= 0.70 or p_score >= 0.70 or s_score >= 0.70 or m_score >= 0.70:
            overall_risk = 'HIGH'
        elif b_severity == 'MEDIUM' or final_threat_score >= 0.35:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'

        # Overall Confidence
        active_scores = [s for s in [b_score, p_score, u_score, m_score, s_score, i_score] if s > 0]
        if active_scores:
            overall_confidence = round(max(active_scores), 3)
        else:
            overall_confidence = 0.95 if overall_risk == 'LOW' else final_threat_score

        # 9. Synthesize Explainable AI (XAI) Evidence
        raw_report = {
            'bullying_analysis': bullying_result,
            'phishing_analysis': phishing_result,
            'url_analysis': url_results,
            'domain_analysis': domain_result,
            'social_eng_analysis': social_result,
            'malware_analysis': malware_result,
            'image_analysis': image_result
        }
        
        evidence = self.xai.generate_explanation(raw_report)
        
        return {
            'email_subject': email_subject,
            'email_from': email_from,
            'email_to': email_to,
            'email_text': email_text,
            'overall_risk_level': overall_risk,
            'overall_confidence': overall_confidence,
            'threat_score': final_threat_score,
            'bullying_analysis': bullying_result,
            'phishing_analysis': phishing_result,
            'url_analysis': url_results,
            'domain_analysis': domain_result,
            'social_eng_analysis': social_result,
            'malware_analysis': malware_result,
            'image_analysis': image_result,
            'evidence': evidence
        }
