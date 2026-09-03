import os
import json
import urllib.request
import urllib.error
import re
import logging

logger = logging.getLogger('bullymail.services.llm_threat_analyzer')

EXPLICIT_THREAT_KEYWORDS = {
    'kill', 'kills', 'killed', 'killing', 'killer',
    'murder', 'murders', 'murdered', 'murdering', 'murderer',
    'die', 'dies', 'died', 'dying', 'death', 'dead',
    'hurt', 'hurts', 'hurting', 'harmed', 'harm',
    'attack', 'attacks', 'attacked', 'attacking',
    'stab', 'stabs', 'stabbed', 'stabbing',
    'shoot', 'shoots', 'shot', 'shooting',
    'beat', 'beats', 'beaten', 'beating',
    'assault', 'assaults', 'assaulted', 'assaulting',
    'strangle', 'choke', 'threaten', 'threatened', 'threatening', 'torture', 'poison',
    'burn', 'punch', 'hit', 'smash', 'slash', 'crush',
    'destroy', 'explode', 'drown', 'hang', 'mutilate'
}

class LLMThreatAnalyzerError(Exception):
    def __init__(self, message, status_code=500):
        super().__init__(message)
        self.status_code = status_code
        self.message = message

class LLMThreatAnalyzer:
    OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
    MODEL_NAME = "nvidia/nemotron-3.5-lightning:free"

    @staticmethod
    def _get_api_key():
        key = os.environ.get("OPENROUTER_API_KEY")
        if not key or not key.strip():
            raise LLMThreatAnalyzerError(
                "OPENROUTER_API_KEY is not configured in the server environment (.env).",
                status_code=500
            )
        return key.strip()

    @classmethod
    def _extract_json_response(cls, raw_content: str, full_text_context: str) -> dict:
        """Robustly extracts classification JSON from Nemotron output, with high-recall threat validation."""
        cleaned = re.sub(r'<think>[\s\S]*?</think>', '', raw_content or '', flags=re.IGNORECASE).strip()

        # Look for ```json ... ``` blocks
        matches = re.findall(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', cleaned, flags=re.IGNORECASE)
        if not matches:
            # Look for any JSON object { ... }
            matches = re.findall(r'(\{[\s\S]*?\})', cleaned)

        parsed_data = None
        for candidate in matches:
            try:
                data = json.loads(candidate)
                if isinstance(data, dict) and ('threat_detected' in data or 'severity' in data or 'explanation' in data):
                    parsed_data = data
                    break
            except Exception:
                continue

        if not parsed_data:
            lower_raw = (raw_content or '').lower()
            is_threat = any(k in lower_raw for k in ('threat detected: yes', 'is a threat', 'is a direct threat', 'death threat', 'physical threat', 'critical threat'))
            parsed_data = {
                "threat_detected": is_threat,
                "severity": "CRITICAL" if is_threat else "LOW",
                "confidence": 0.90 if is_threat else 0.85,
                "threat_categories": ["Physical Threat"] if is_threat else [],
                "explanation": raw_content[:250].strip() if raw_content else "LLM classification completed."
            }

        # Normalize and validate fields
        threat_detected = bool(parsed_data.get('threat_detected', False))
        severity = str(parsed_data.get('severity', 'LOW')).upper()
        if severity not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            severity = 'CRITICAL' if threat_detected else 'LOW'

        try:
            confidence = float(parsed_data.get('confidence', 0.85))
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.90 if threat_detected else 0.85

        categories = parsed_data.get('threat_categories')
        if not isinstance(categories, list):
            categories = [str(categories)] if categories else []

        explanation = str(parsed_data.get('explanation', '')).strip()
        if not explanation:
            explanation = "Direct threat identified based on linguistic threat semantics." if threat_detected else "No malicious threat vectors or bullying patterns detected."

        # High-Recall Safety Rule: If input has explicit violent language, enforce high recall
        tokens = set(re.findall(r'\b[a-zA-Z]+\b', (full_text_context or '').lower()))
        threat_overlap = tokens.intersection(EXPLICIT_THREAT_KEYWORDS)
        if threat_overlap and not threat_detected:
            threat_detected = True
            severity = 'CRITICAL'
            confidence = max(confidence, 0.95)
            if "Physical Threat" not in categories:
                categories.append("Physical Threat")
            explanation = f"Explicit high-risk threat terminology identified ({', '.join(sorted(threat_overlap))})."

        return {
            "threat_detected": threat_detected,
            "severity": severity,
            "confidence": round(confidence, 2),
            "threat_categories": categories,
            "explanation": explanation,
            "model": cls.MODEL_NAME
        }

    @classmethod
    def analyze(cls, email_text: str, email_subject: str = "", email_from: str = "", email_to: str = "") -> dict:
        api_key = cls._get_api_key()

        full_context = f"Subject: {email_subject}\nFrom: {email_from}\nTo: {email_to}\nBody:\n{email_text}".strip()

        system_instruction = (
            "You are an advanced cybersecurity AI forensic engine specializing in email threat intelligence, harassment, and violence detection.\n"
            "Analyze the provided email and classify it for threat, violence, and bullying risk.\n\n"
            "CRITICAL RULES:\n"
            "1. If the email contains explicit violent threats, death threats, or intent to harm/attack/kill (e.g., 'You will be killed', 'I will murder you', 'I will shoot you', 'I am going to stab you', 'You are going to die'):\n"
            "   - threat_detected: true\n"
            "   - severity: 'CRITICAL'\n"
            "   - confidence: 0.90 to 1.00\n"
            "   - threat_categories: ['Physical Threat']\n"
            "2. If the email is benign, neutral, or clean:\n"
            "   - threat_detected: false\n"
            "   - severity: 'LOW'\n"
            "   - confidence: 0.90 to 1.00\n"
            "   - threat_categories: []\n\n"
            "Respond ONLY with a valid JSON object matching this schema:\n"
            "{\n"
            '  "threat_detected": true/false,\n'
            '  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",\n'
            '  "confidence": 0.95,\n'
            '  "threat_categories": ["Physical Threat"],\n'
            '  "explanation": "Concise justification string (1-2 sentences)"\n'
            "}"
        )

        payload = {
            "model": cls.MODEL_NAME,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": full_context}
            ],
            "temperature": 0.1,
            "max_tokens": 1200
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:5000",
            "X-Title": "BullyMail Threat Intelligence",
            "User-Agent": "BullyMail-Security-Platform/2.0"
        }

        req = urllib.request.Request(
            cls.OPENROUTER_ENDPOINT,
            data=json.dumps(payload).encode('utf-8'),
            headers=headers,
            method='POST'
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status_code = resp.getcode()
                raw_body = resp.read().decode('utf-8')
                data = json.loads(raw_body)
                raw_content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                result = cls._extract_json_response(raw_content, full_context)
                return result
        except urllib.error.HTTPError as e:
            err_text = e.read().decode('utf-8', errors='ignore')
            logger.error(f"OpenRouter HTTP Error {e.code}: {err_text}")
            if e.code == 401:
                raise LLMThreatAnalyzerError("OpenRouter Authentication failed: Invalid API key.", status_code=401)
            elif e.code == 429:
                raise LLMThreatAnalyzerError("OpenRouter Rate limit exceeded (429). Please wait a moment and retry.", status_code=429)
            elif e.code >= 500:
                raise LLMThreatAnalyzerError(f"OpenRouter upstream server error ({e.code}). Please retry.", status_code=502)
            else:
                raise LLMThreatAnalyzerError(f"OpenRouter API request error ({e.code}): {err_text[:200]}", status_code=e.code)
        except urllib.error.URLError as e:
            logger.error(f"OpenRouter Connection Error: {e}")
            raise LLMThreatAnalyzerError("Failed to connect to OpenRouter API (Network timeout or connection error).", status_code=504)
        except Exception as e:
            logger.error(f"OpenRouter Unexpected Error: {e}")
            raise LLMThreatAnalyzerError(f"AI / LLM Analysis failed: {str(e)}", status_code=500)
