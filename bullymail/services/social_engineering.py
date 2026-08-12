import re
import math

class SocialEngineeringDetector:
    """Social Engineering & Psychological Manipulation Detection Engine"""
    
    TECHNIQUES = {
        'Authority Impersonation': {
            'patterns': [
                r'\b(from\s+the\s+office\s+of\s+the\s+(dean|provost|chancellor|president|director|board))\b',
                r'\b(official\s+notice\s+from\s+(it\s+security|administration|department\s+chair|academic\s+affairs))\b',
                r'\b(campus\s+police|law\s+enforcement|legal\s+counsel|compliance\s+officer)\b',
                r'\b(as\s+instructed\s+by\s+the\s+(ceo|board|dean|faculty\s+head|provost))\b'
            ],
            'weight': 0.35,
            'severity': 'HIGH'
        },
        'Urgency & Time Pressure': {
            'patterns': [
                r'\b(urgent\s+response\s+required|immediate\s+action\s+needed|act\s+without\s+delay|without\s+delay)\b',
                r'\b(must\s+be\s+completed\s+(today|within\s+\d+\s+hours?|by\s+end\s+of\s+day))\b',
                r'\b(do\s+not\s+delay|time\s+is\s+running\s+out|final\s+notice|limited\s+time\s+offer)\b',
                r'\b(claim\s+(your\s+)?(prize|reward|grant|funds|gift|bonus)?\s*(immediately|now|today))\b',
                r'\b(immediate(ly)?|urgent(ly)?)\b'
            ],
            'weight': 0.25,
            'severity': 'MEDIUM'
        },
        'Fear, Intimidation & Coercion': {
            'patterns': [
                r'\b(legal\s+action\s+will\s+be\s+taken|court\s+summons|arrest\s+warrant)\b',
                r'\b(you\s+will\s+be\s+(expelled|suspended|terminated|prosecuted|fired|reported))\b',
                r'\b(consequences\s+will\s+be\s+severe|disciplinary\s+hearing\s+scheduled)\b',
                r'\b(your\s+reputation\s+will\s+be\s+damaged|you\s+have\s+been\s+recorded)\b'
            ],
            'weight': 0.40,
            'severity': 'CRITICAL'
        },
        'Financial Coercion & Pressure': {
            'patterns': [
                r'\b(transfer\s+funds\s+immediately|send\s+payment\s+urgently|unpaid\s+fine)\b',
                r'\b(purchase\s+(gift\s+cards?|itunes|amazon\s+cards?)\s+and\s+send\s+codes)\b',
                r'\b(penalty\s+fee\s+of\s+\$?\d+|overdue\s+penalty\s+charges)\b'
            ],
            'weight': 0.35,
            'severity': 'CRITICAL'
        },
        'Reward & Greed Manipulation': {
            'patterns': [
                r'\b(you\s+(have\s+been|were)\s+awarded\s+(a\s+)?(grant|scholarship|prize|stipend|fellowship|bonus|gift|payout)(\s+of\s+\$?\d+)?)\b',
                r'\b(congratulations!?[^.!?\n]*(you\s+won|awarded|selected|eligible|winner|grant|prize))\b',
                r'\b(claim\s+(your\s+)?(prize|reward|grant|funds|gift|bonus|stipend|payout|settlement|winnings))\b',
                r'\b(unclaimed\s+(lottery|funds|prize|grant)|exclusive\s+cash\s+offer)\b',
                r'\b(work-from-home\s+(assistant\s+position|position|job)\s+\$?\d+\s*/\s*week)\b'
            ],
            'weight': 0.35,
            'severity': 'HIGH'
        },
        'Fake Account Warning / Pretext': {
            'patterns': [
                r'\b(unauthorized\s+access\s+from\s+another\s+(device|location|ip))\b',
                r'\b(account\s+will\s+be\s+(deactivated|deleted)\s+due\s+to\s+inactivity)\b',
                r'\b(mailbox\s+quota\s+exceeded|server\s+storage\s+full)\b'
            ],
            'weight': 0.30,
            'severity': 'HIGH'
        }
    }

    def analyze(self, text, subject=""):
        """Analyzes email content for psychological manipulation and social engineering tactics."""
        if not text and not subject:
            return {
                'risk_level': 'LOW',
                'confidence': 0.0,
                'threat_score': 0.0,
                'techniques': [],
                'explanation': 'No text provided for analysis.'
            }
            
        full_content = f"{subject} {text}".lower()
        detected_techniques = []
        raw_score = 0.0
        
        has_reward = False
        has_urgency = False
        has_fear = False
        has_authority = False
        
        for name, config in self.TECHNIQUES.items():
            matched_phrases = []
            for pat in config['patterns']:
                matches = re.findall(pat, full_content)
                if matches:
                    for m in matches:
                        phrase = m[0] if isinstance(m, tuple) else m
                        if phrase not in matched_phrases:
                            matched_phrases.append(phrase)
                            
            if matched_phrases:
                raw_score += config['weight']
                detected_techniques.append({
                    'name': name,
                    'severity': config['severity'],
                    'evidence': matched_phrases
                })
                if name == 'Reward & Greed Manipulation':
                    has_reward = True
                elif name == 'Urgency & Time Pressure':
                    has_urgency = True
                elif name == 'Fear, Intimidation & Coercion':
                    has_fear = True
                elif name == 'Authority Impersonation':
                    has_authority = True

        # Synergy Bonuses
        if has_reward and has_urgency:
            raw_score += 0.20  # Classic advance fee / prize lure + urgency combo
        if has_authority and (has_fear or has_urgency):
            raw_score += 0.25  # Classic executive/dean authority coercion combo

        confidence = round(1.0 - math.exp(-1.4 * raw_score), 3) if raw_score > 0 else 0.0
        
        if confidence >= 0.70 or (has_authority and has_fear):
            risk_level = 'CRITICAL' if any(t['severity'] == 'CRITICAL' for t in detected_techniques) else 'HIGH'
        elif confidence >= 0.35 or has_reward or has_authority or has_fear:
            risk_level = 'MEDIUM'
            confidence = max(confidence, 0.45)
        else:
            risk_level = 'LOW'
            
        if risk_level == 'LOW':
            explanation = "No overt psychological pressure or social engineering manipulation detected."
        else:
            tech_names = [t['name'] for t in detected_techniques]
            explanation = f"Detected {len(detected_techniques)} social engineering technique(s): {', '.join(tech_names)}."
            
        return {
            'risk_level': risk_level,
            'confidence': confidence,
            'threat_score': round(min(raw_score, 1.0), 3),
            'techniques': detected_techniques,
            'explanation': explanation
        }
