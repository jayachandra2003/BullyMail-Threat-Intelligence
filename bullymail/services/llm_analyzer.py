"""
BullyMail — LLM Threat Analysis Service
========================================
Routes analysis requests through OpenRouter (NVIDIA Nemotron-3.5) as an
ISOLATED, ALTERNATIVE analysis engine for the Threat Analyzer only.

IMPORTANT:
- This module does NOT modify the existing ML/TF-IDF pipeline.
- LLM results are TRANSIENT — never saved to the database.
- The OpenRouter API key is read from the environment and is NEVER logged,
  returned in API responses, or exposed to the browser.

Privacy note:
  AI/LLM mode using the free OpenRouter endpoint is intended for
  synthetic/demo data. Do not submit confidential or personal university
  email content.
"""

import os
import json
import re
import urllib.request
import urllib.error

_OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
_OPENROUTER_MODEL = "nvidia/nemotron-3.5-lightning:free"
_REQUEST_TIMEOUT_SECONDS = 45

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_VALID_RISK_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


class LLMAnalysisError(Exception):
    def __init__(self, user_message: str):
        super().__init__(user_message)
        self.user_message = user_message


def _build_classification_prompt(email_text, email_subject, email_from, email_to):
    context_parts = []
    if email_subject:
        context_parts.append(f"Subject: {email_subject}")
    if email_from:
        context_parts.append(f"From: {email_from}")
    if email_to:
        context_parts.append(f"To: {email_to}")
    if email_text:
        context_parts.append(f"Body:\n{email_text}")
    email_context = "\n".join(context_parts) if context_parts else "(no content provided)"

    prompt = f"""You are a cybersecurity threat classification engine for an academic institution email security platform.

Analyze the following email and classify it across five threat vectors. Return ONLY a valid JSON object — no markdown, no explanation, no prose outside the JSON.

EMAIL TO ANALYZE:
---
{email_context}
---

CLASSIFICATION TASK:
Classify the email for each of these five threat categories:
1. cyberbullying — harassment, targeted abuse, insults, intimidation, humiliation
2. threat — explicit violent language, physical threats, death threats
3. phishing — credential harvesting, deceptive links, spoofed identities, urgency scams
4. link_safety — suspicious URLs, IP-based links, homograph/typosquatting domains
5. social_engineering — psychological manipulation, urgency, authority impersonation, coercion

THREAT DETECTION REQUIREMENT (HIGH RECALL):
For the "threat" category, you MUST recognize all grammatical forms of violent language, including but not limited to:
Kill/kills/killed/killing, Murder/murders/murdered/murdering, Die/dies/died/dying/death/dead, Hurt/hurts/hurting, Harm/harmed/harming, Attack/attacked/attacking, Stab/stabbed/stabbing, Shoot/shot/shooting, Beat/beaten/beating, Assault/assaulted/assaulting, Strangle/strangled/strangling, Choke/choked/choking, Threaten/threatened/threatening, Torture/tortured/torturing, Poison/poisoned/poisoning, Burn/burned/burning, Punch/punched/punching, Smash/smashed/smashing, Slash/slashed/slashing, Crush/crushed/crushing, Destroy/destroyed/destroying, Explode/exploded/exploding, Drown/drowned/drowning, Mutilate/mutilated/mutilating.

Examples that MUST be identified as threat content:
- "You will be killed", "I will murder you", "I'll kill you", "I am going to stab you"
- "I'll shoot you", "You are going to die", "I will hurt you", "I am going to attack you"

This system requires high-recall threat detection. Report detected threat language even if it appears in casual or indirect form.

RESPONSE FORMAT — return exactly this JSON structure with no additional text:
{{
  "cyberbullying": {{"detected": true or false, "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0.0, "reason": "brief explanation"}},
  "threat": {{"detected": true or false, "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0.0, "reason": "brief explanation"}},
  "phishing": {{"detected": true or false, "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0.0, "reason": "brief explanation"}},
  "link_safety": {{"detected": true or false, "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0.0, "reason": "brief explanation"}},
  "social_engineering": {{"detected": true or false, "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0.0, "reason": "brief explanation"}},
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "overall_score": 0.0,
  "summary": "one-sentence summary of the email threat assessment"
}}"""
    return prompt


def _parse_llm_response(raw_text):
    if not raw_text or not raw_text.strip():
        raise LLMAnalysisError("AI analysis returned an empty response. Please try again.")

    parsed = None
    try:
        parsed = json.loads(raw_text.strip())
    except json.JSONDecodeError:
        pass

    if parsed is None:
        match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

    if not isinstance(parsed, dict):
        raise LLMAnalysisError(
            "AI analysis returned an unreadable response format. "
            "Please try again or switch to Normal mode."
        )

    categories = ["cyberbullying", "threat", "phishing", "link_safety", "social_engineering"]
    for cat in categories:
        if cat not in parsed or not isinstance(parsed[cat], dict):
            parsed[cat] = {"detected": False, "severity": "LOW", "confidence": 0.0, "reason": "No data returned by model."}
        else:
            d = parsed[cat]
            d["detected"] = bool(d.get("detected", False))
            sev = str(d.get("severity", "LOW")).upper()
            d["severity"] = sev if sev in _VALID_SEVERITIES else "LOW"
            try:
                conf = float(d.get("confidence", 0.0))
                d["confidence"] = max(0.0, min(1.0, conf))
            except (TypeError, ValueError):
                d["confidence"] = 0.0
            d["reason"] = str(d.get("reason", ""))[:500]

    overall_risk = str(parsed.get("overall_risk", "LOW")).upper()
    if overall_risk not in _VALID_RISK_LEVELS:
        overall_risk = "LOW"

    try:
        overall_score = float(parsed.get("overall_score", 0.0))
        overall_score = max(0.0, min(1.0, overall_score))
    except (TypeError, ValueError):
        overall_score = 0.0

    summary = str(parsed.get("summary", ""))[:1000]

    return {
        "cyberbullying": parsed["cyberbullying"],
        "threat": parsed["threat"],
        "phishing": parsed["phishing"],
        "link_safety": parsed["link_safety"],
        "social_engineering": parsed["social_engineering"],
        "overall_risk": overall_risk,
        "overall_score": overall_score,
        "summary": summary,
    }


def _call_openrouter(api_key, prompt):
    payload = {
        "model": _OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 800,
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(_OPENROUTER_API_URL, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("HTTP-Referer", "https://bullymail.local")
    req.add_header("X-Title", "BullyMail Threat Analyzer")

    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:
            response_body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise LLMAnalysisError(
                "AI analysis failed: OpenRouter authentication error. "
                "Check the OPENROUTER_API_KEY configuration."
            )
        elif e.code == 429:
            raise LLMAnalysisError(
                "AI analysis failed: OpenRouter rate limit reached. "
                "Please wait a moment and try again."
            )
        else:
            raise LLMAnalysisError(
                "AI analysis is currently unavailable. "
                "Check the OpenRouter configuration."
            )
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "timed out" in reason.lower() or "timeout" in reason.lower():
            raise LLMAnalysisError(
                "AI analysis timed out. The OpenRouter service did not respond in time. "
                "Please try again or switch to Normal mode."
            )
        raise LLMAnalysisError(
            "AI analysis is currently unavailable. Check the OpenRouter configuration."
        )
    except OSError:
        raise LLMAnalysisError(
            "AI analysis is currently unavailable. Check the OpenRouter configuration."
        )

    try:
        envelope = json.loads(response_body)
    except json.JSONDecodeError:
        raise LLMAnalysisError("AI analysis returned an unexpected response format. Please try again.")

    try:
        content = envelope["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise LLMAnalysisError("AI analysis returned an unexpected response structure. Please try again.")

    return content


class LLMAnalyzer:
    """
    Isolated LLM-based email threat analysis engine using OpenRouter / NVIDIA Nemotron.

    This is an ALTERNATIVE engine for the Threat Analyzer only.
    It does NOT modify the ML pipeline, training data, models, or database.
    Results are transient — not saved to the database.
    """

    def analyze(self, email_text="", email_subject="", email_from="", email_to=""):
        """
        Classify email via OpenRouter LLM. Returns structured report dict.
        Raises LLMAnalysisError on any failure.
        """
        # Read key from environment — never from a shared config object
        api_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
        if not api_key:
            raise LLMAnalysisError(
                "AI analysis is unavailable: OPENROUTER_API_KEY is not configured. "
                "Please add it to your .env file."
            )

        prompt = _build_classification_prompt(
            email_text=email_text,
            email_subject=email_subject,
            email_from=email_from,
            email_to=email_to,
        )
        raw_content = _call_openrouter(api_key, prompt)
        result = _parse_llm_response(raw_content)
        result["engine"] = "llm"
        result["model"] = _OPENROUTER_MODEL
        return result
