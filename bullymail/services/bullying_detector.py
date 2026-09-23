import os
import re
import math
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, confusion_matrix
from ..config import Config
from .preprocessor import TextPreprocessor

# -------------------------------------------------------------------------
# Categorized Cyberbullying, Harassment & Threat Taxonomy
# -------------------------------------------------------------------------

# 1. Tier 1: Explicit Physical Harm, Violent Threat Word Families & Intimidation (CRITICAL Severity)
PHYSICAL_THREAT_PATTERNS = [
    # Direct / Constructed 1st, 2nd, 3rd person threats and passive verb forms
    (r'\b(you(\s+will|\'ll|\s+are\s+going\s+to|\'re\s+gonna)?\s+(be|get)\s+(killed|murdered|shot|stabbed|beaten|assaulted|attacked|strangled|choked|tortured|poisoned|burned|hung|hanged|drowned|mutilated|slaughtered|executed|destroyed))\b', 'Passive Voice Violence Threat', 0.95),
    (r"\b(i(\'ll|\s+will|\s+am\s+going\s+to|'m\s+gonna)|\bwe(\'ll|\s+will|\s+are\s+going\s+to))\s+(hurt|kill|harm|attack|beat|assault|punch|stab|destroy|murder|hunt|shoot|strangle|choke|torture|poison|burn|slash|crush|drown|hang|mutilate|slaughter|execute)\s+(you|u|him|her|them)\b", 'Direct 1st-Person Physical Violence Threat', 0.95),
    (r'\b(you(\'ll|\s+will|\s+are\s+going\s+to|\'re\s+gonna)\s+(die|pay|suffer|bleed|regret\s+this|perish))\b', 'Direct Intimidation / Death Threat', 0.95),
    (r'\b(i\s+(want|need|wish)\s+(you|u)\s+(dead|killed|to\s+die))\b', 'Expressed Death Wish / Threat', 0.95),
    (r'\b(threaten(s|ed|ing)?\s+to\s+(kill|murder|hurt|harm|stab|shoot|attack|beat|destroy|ruin|assault))\b', 'Threatening Action Signal', 0.92),
    (r'\b(if\s+you\s+(don\'t|do\s+not)|unless\s+you)\s+.*?\s+(i(\'ll|\s+will)|\bwe(\'ll|\s+will))\s+(hurt|kill|harm|beat|destroy|ruin|attack|stab|shoot)\s+(you|u)\b', 'Coercive Harm Threat', 0.95),
    (r'\b(watch\s+your\s+back|you\s+will\s+pay\s+for\s+this|you\s+won\'t\s+be\s+safe|i\s+know\s+where\s+you\s+live|you\s+are\s+dead|make\s+you\s+suffer|better\s+watch\s+(out|yourself))\b', 'Intimidation / Stalking Threat', 0.92),
    (r'\b(kys|kill\s+yourself|go\s+die|drink\s+bleach|hang\s+yourself|slit\s+your\s+wrists?)\b', 'Suicide Encouragement / Coercive Harm', 0.95),
    (r'\b(i\s+will\s+make\s+sure\s+you\s+(fail|are\s+expelled|get\s+fired|are\s+dismissed|regret\s+this))\b', 'Direct Retaliation Threat', 0.88),
    (r'\b(ruin\s+your\s+life|destroy\s+your\s+future|end\s+your\s+career)\b', 'Severe Life / Career Destruction Threat', 0.88),

    # High-Recall Word Families (Covers all morphological forms, verbs, nouns, and participles)
    # KILL family: kill, kills, killed, killing, killer, killers
    (r'\b(kill|kills|killed|killing|killer|killers)\b', 'Threat Word Family: KILL', 0.90),
    # MURDER family: murder, murders, murdered, murdering, murderer, murderers
    (r'\b(murder|murders|murdered|murdering|murderer|murderers)\b', 'Threat Word Family: MURDER', 0.90),
    # DIE / DEATH family: die, dies, died, dying, death, dead
    (r'\b(die|dies|died|dying|death|dead)\b', 'Threat Word Family: DIE/DEATH', 0.88),
    # HURT / HARM family: hurt, hurts, hurting, harm, harms, harmed, harming
    (r'\b(hurt|hurts|hurting|harm|harms|harmed|harming)\b', 'Threat Word Family: HURT/HARM', 0.88),
    # STAB family: stab, stabs, stabbed, stabbing, stabber, stabbers
    (r'\b(stab|stabs|stabbed|stabbing|stabber|stabbers)\b', 'Threat Word Family: STAB', 0.90),
    # SHOOT family: shoot, shoots, shot, shooting, shooter, shooters
    (r'\b(shoot|shoots|shot|shooting|shooter|shooters)\b', 'Threat Word Family: SHOOT', 0.90),
    # BEAT / ASSAULT family: beat, beats, beaten, beating, assault, assaults, assaulted, assaulting, assailant
    (r'\b(beat|beats|beaten|beating|assault|assaults|assaulted|assaulting|assailant|assailants)\b', 'Threat Word Family: BEAT/ASSAULT', 0.88),
    # ATTACK family: attack, attacks, attacked, attacking, attacker, attackers
    (r'\b(attack|attacks|attacked|attacking|attacker|attackers)\b', 'Threat Word Family: ATTACK', 0.88),
    # STRANGLE / CHOKE family: strangle, strangles, strangled, strangling, strangler, choke, chokes, choked, choking, suffocate, suffocated
    (r'\b(strangle|strangles|strangled|strangling|strangler|stranglers|choke|chokes|choked|choking|suffocate|suffocates|suffocated|suffocating|asphyxiate|asphyxiated)\b', 'Threat Word Family: STRANGLE/CHOKE', 0.90),
    # THREATEN family: threaten, threatens, threatened, threatening, threat, threats, intimidate, intimidated, intimidating
    (r'\b(threaten|threatens|threatened|threatening|threat|threats|intimidate|intimidates|intimidated|intimidating|intimidation)\b', 'Threat Word Family: THREATEN', 0.88),
    # TORTURE family: torture, tortures, tortured, torturing, torturer, torturers
    (r'\b(torture|tortures|tortured|torturing|torturer|torturers)\b', 'Threat Word Family: TORTURE', 0.90),
    # POISON family: poison, poisons, poisoned, poisoning, poisonous
    (r'\b(poison|poisons|poisoned|poisoning|poisonous)\b', 'Threat Word Family: POISON', 0.88),
    # BURN / ARSON family: burn, burns, burned, burning, arson, immolate, immolated
    (r'\b(burn|burns|burned|burning|arson|immolate|immolated)\b', 'Threat Word Family: BURN', 0.88),
    # PUNCH / HIT family: punch, punches, punched, punching, hit, hits, hitting, batter, battered, battering
    (r'\b(punch|punches|punched|punching|hit|hits|hitting|batter|batters|battered|battering)\b', 'Threat Word Family: PUNCH/HIT', 0.88),
    # SMASH / SLASH / CRUSH family: smash, smashes, smashed, smashing, slash, slashes, slashed, slashing, crush, crushes, crushed, crushing
    (r'\b(smash|smashes|smashed|smashing|slash|slashes|slashed|slashing|crush|crushes|crushed|crushing)\b', 'Threat Word Family: SMASH/SLASH/CRUSH', 0.88),
    # DESTROY / EXPLODE / BOMB family: destroy, destroys, destroyed, destroying, destruction, explode, explodes, exploded, exploding, bomb, bombs, bombed, bombing
    (r'\b(destroy|destroys|destroyed|destroying|destruction|explode|explodes|exploded|exploding|explosion|bomb|bombs|bombed|bombing|bomber|bombers)\b', 'Threat Word Family: DESTROY/EXPLODE', 0.88),
    # DROWN / HANG / MUTILATE family: drown, drowns, drowned, drowning, hang, hangs, hanged, hanging, mutilate, mutilates, mutilated, mutilating
    (r'\b(drown|drowns|drowned|drowning|hang|hangs|hanged|hanging|mutilate|mutilates|mutilated|mutilating|mutilation)\b', 'Threat Word Family: DROWN/HANG/MUTILATE', 0.90),
    # EXECUTE / SLAUGHTER / MASSACRE / BEHEAD family: behead, beheaded, beheading, decapitate, decapitated, slaughter, slaughtered, massacre, massacred, execute, executed, assassinate, assassinated
    (r'\b(behead|beheads|beheaded|beheading|decapitate|decapitates|decapitated|decapitating|slaughter|slaughters|slaughtered|slaughtering|massacre|massacres|massacred|massacring|execute|executes|executed|executing|execution|assassinate|assassinates|assassinated|assassinating|assassination)\b', 'Threat Word Family: EXECUTE/SLAUGHTER', 0.90)
]

# 2. Tier 2: Severe Abusive Language & Hostile Profanity (HIGH Severity)
SEVERE_ABUSIVE_PATTERNS = [
    (r'\b(mother[\s\-_]?fuck(er|ers|ing|ed)?)\b', 'Severe Profane Abuse', 0.85),
    (r'\b(fuck\s+(you|off|u))\b', 'Aggressive Hostile Attack', 0.85),
    (r'\b(shut\s+the\s+fuck\s+up|stfu)\b', 'Aggressive Silencing Attack', 0.80),
    (r'\b(son\s+of\s+a\s+bitch|piece\s+of\s+shit|pos)\b', 'Severe Personal Degradation', 0.80),
    (r'\b(asshole|bastard|cunt|dickhead|dipshit|scumbag|jackass|douchebag|twat|wanker|bitch|slut|whore)\b', 'Severe Personal Epithet', 0.78),
    (r'\b(go\s+to\s+hell|rot\s+in\s+hell|eat\s+shit|drop\s+dead)\b', 'Hostile Degradation / Curse', 0.78),
    (r'\b(fucking\s+(idiot|moron|loser|fool|liar|coward|failure|bitch|bastard|useless|piece\s+of\s+shit|joke|pig|dog|rat|scum))\b', 'Targeted Profane Insult', 0.85)
]

# 2b. Tier 2b: Dehumanizing, Racial, Discriminatory & Hate Harassment (HIGH Severity)
DEHUMANIZING_DISCRIMINATORY_PATTERNS = [
    # Racial, ethnic, skin-color, or identity-based dehumanizing attacks
    (r'\b(you\s+)?(black|white|dark|yellow|brown)\s+skin(ned)?\s+(pig|dog|ape|monkey|rat|animal|scum|trash|bastard|freak|subhuman)\b', 'Dehumanizing Racial / Identity Harassment', 0.88),
    (r'\b(black|white|dark|yellow|brown)\s+skin(ned)?\s+(pig|dog|ape|monkey|rat|animal|scum|trash)\b', 'Dehumanizing Racial / Identity Harassment', 0.88),

    # Dehumanizing animal/object epithets targeted at a person ("you ... pig", "you ... dog", "you ... rat")
    (r'\b(you(\s+are|\'re|r)?\s+(a\s+|an\s+|so\s+|totally\s+|completely\s+|utterly\s+|filthy\s+|dirty\s+|ugly\s+|greedy\s+|lazy\s+|disgusting\s+)?(pig|dog|rat|ape|monkey|swine|animal|parasite|subhuman|vermin))\b', 'Dehumanizing Personal Attack', 0.85),
    (r'\b(you\s+(pig|dog|rat|ape|monkey|swine|parasite|subhuman|vermin))\b', 'Dehumanizing Direct Vocative', 0.85),
    (r'\b(filthy|dirty|ugly|disgusting)\s+(pig|dog|rat|ape|swine|animal|subhuman|vermin)\b', 'Dehumanizing Degradation', 0.82),

    # Targeted identity / racial degradation
    (r'\b(racist|sexist|bigoted)\s+(pig|dog|scum|trash|bastard|asshole)\b', 'Discriminatory Personal Attack', 0.80),
]

# 3. Tier 3: Targeted Insults & Personal Demeaning (Single: MEDIUM Severity, Multiple: HIGH Severity)
TARGETED_INSULT_PATTERNS = [
    # Full sentence personal attacks
    (r'\b(you(\s+are|\'re|r)?\s+(a\s+|an\s+|so\s+|totally\s+|completely\s+|utterly\s+)?(idiot|stupid|moron|loser|useless|pathetic|fool|incompetent|joke|failure|clueless|moronic|worthless|hopeless|garbage|disaster|imbecile|dumbass|ignorant|dumb|jerk|pig|swine|dog|rat|scum|trash|freak|psycho|creep))\b', 'Targeted Personal Insult', 0.58),
    (r'\b(you\s+(idiot|moron|loser|fool|imbecile|dumbass|clown|jerk|failure|scumbag|pig|swine|dog|rat|scum|trash|freak|psycho|creep))\b', 'Direct Vocative Insult', 0.58),
    
    # Standalone direct lexical insults (inherently hostile offensive nouns)
    (r'\b(idiot|moron|imbecile|loser|dumbass|fool|useless|incompetent|dumb|worthless)\b', 'Direct Lexical Insult', 0.58),
    
    # Standalone single-word "pathetic"
    (r'^\s*pathetic[\.!\?]*\s*$', 'Direct Lexical Insult', 0.58),
    
    # Targeted personal / work references with "pathetic" (avoids matching untargeted literary "pathetic flaw/fallacy")
    (r'\b(you|he|she|they|[a-z]+)\s+(is|are|\'re|\'s)\s+(a\s+|an\s+|so\s+|totally\s+|completely\s+|utterly\s+|truly\s+|just\s+)?pathetic\b', 'Targeted Personal Insult', 0.58),
    (r'\b(stop\s+being\s+pathetic|so\s+pathetic|such\s+a\s+pathetic\s+(loser|effort|attempt|joke|person|student|excuse|work))\b', 'Targeted Personal Insult', 0.58),
    (r'\b(that|this)\s+pathetic\s+(loser|student|person|joke|idiot|fool|clown)\b', 'Targeted Personal Insult', 0.58),
    (r'\b(that\s+was|such\s+a)\s+pathetic\s+(effort|attempt|job|performance|work|submission)\b', 'Targeted Personal Insult', 0.58),
    (r'\b(your\s+[a-z0-9_]+\s+is\s+pathetic)\b', 'Hostile Academic Invalidation', 0.65),

    # Demeaning statements and exclusion
    (r'\b(you(\s+are|\'re|r)?\s+(an?\s+)?(academic\s+fraud|waste\s+of\s+(space|time|resources|tuition|energy)))\b', 'Severe Personal Demeaning', 0.70),
    (r'\b(nobody|no\s*one|everyone)\s+(likes|wants|respects|cares\s+about|hates)\s+you\b', 'Social Exclusion / Isolation', 0.65),
    (r'\b(you\s+should|why\s+don\'t\s+you)\s+(quit|drop\s+out|give\s+up|leave|disappear|resign|get\s+lost)(\s+immediately|\s+now)?\b', 'Exclusion / Coerced Quitting', 0.65),
    (r'\b(you(\s+will|\'ll)?\s+never\s+(succeed|amount\s+to\s+anything|pass|graduate|make\s+it|get\s+a\s+(job|recommendation|position)))\b', 'Futile Future / Demoralization', 0.60),
    (r'\b(can\'t|cannot|cant)\s+do\s+anything\s+right\b', 'Competence Invalidation', 0.60),
    (r'\b(useless|worthless|failure|pathetic|embarrassing)\s+(student|researcher|person|effort|attempt)\b', 'Demeaning Student Label', 0.60)
]

# 4. Tier 4: Academic Hostility & Invalidation (MEDIUM to HIGH Severity)
ACADEMIC_HOSTILITY_PATTERNS = [
    (r'\b(your\s+(research|work|thesis|paper|assignment|proposal|performance|code|submission)\s+is\s+(a\s+complete\s+failure|pathetic|worthless|garbage|a\s+joke|disgraceful|an\s+embarrassment|utterly\s+useless))\b', 'Hostile Academic Invalidation', 0.65),
    (r'\b(stop\s+embarrassing\s+yourself\s+with\s+(this|your)\s+(pathetic|worthless|garbage|terrible)\s+(work|paper|research|submission))\b', 'Hostile Academic Invalidation', 0.65),
    (r'\b(everyone\s+knows\s+you\s+(are|\'re)\s+too\s+(stupid|dumb|incompetent)\s+to\s+(pass|graduate|succeed))\b', 'Academic Gatekeeping / Undermining', 0.70),
    (r'\b(not\s+(cut\s+out\s+for|smart\s+enough\s+for|capable\s+of)\s+(this|academia|graduate\s+school|university|research|the\s+program|our\s+lab))\b', 'Academic Gatekeeping / Undermining', 0.60),
    (r'\b(intellectually\s+deficient|academic\s+fraud|conceptually\s+bankrupt|methodologically\s+incompetent)\b', 'Academic Harassment', 0.65)
]

# 5. Tier 5: Mild / Expressive Colloquial Profanity (Low weight: 0.20, non-bullying on its own)
MILD_PROFANITY_PATTERNS = [
    (r'\b(damn|crap|hell|pissed|sucks|bullshit|freaking|bloody)\b', 'Mild / Colloquial Profanity', 0.20)
]

# 6. Educational / Linguistic / Quoted Context Filters (Prevents False Positives)
EDUCATIONAL_CONTEXT_PATTERNS = [
    r'\b(in\s+(our|the|this)\s+(linguistics|english|literature|sociology|psychology|language|research)\s+(class|course|paper|study|seminar|lecture|analysis|context))\b',
    r'\b(analyz(ing|ed)|discuss(ing|ed)|stud(ying|ed)|etymology\s+of|definition\s+of|usage\s+of|origin\s+of)\s+(the\s+word|the\s+term|the\s+phrase|taboo\s+words?|profan(ity|e)|slurs?|vulgar(ity)?)\b',
    r'\b(quoted|quoting|citation|literature\s+review|transcribed\s+audio|dialogue\s+from|historical\s+texts?)\b'
]

# 7. Reporting & Incident Attribution Context Patterns
REPORTING_CONTEXT_PATTERNS = [
    # Document as subject with reporting / containment verbs
    r'\bthe\s+(complaint|incident\s+report|report|grievance|filing|document|record|case)\s+(states|indicates|notes|alleges|mentions|records|contains|quotes|includes)\s+(that|the\s+phrase|the\s+words?|the\s+statement|the\s+sender)?\b',
    r'\b(states|indicates|notes|alleges)\s+that\s+[a-z0-9_\s]+\s+(was\s+called|called|stated|said|wrote|messaged|insulted|threatened)\b',
    r'\b(quotes|records)\s+the\s+(sender|user|author|person)\s+(saying|writing|stating)\b',
    r'\bthe\s+(student|complainant|victim|witness|employee|user|person|sender)\s+(wrote|said|stated|reported|alleged|claimed|testified|submitted)\b',
    r'\bin\s+the\s+(complaint|incident\s+report|formal\s+complaint|grievance|investigation|disciplinary\s+report|police\s+report)\b',
    r'\baccording\s+to\s+the\s+(complaint|incident\s+report|report|investigation|testimony)\b',
    r'\breported\s+that\s+[a-z0-9_\s]+\s+(called|stated|said|wrote|messaged|insulted|threatened)\b',
    r'\balleged\s+that\s+[a-z0-9_\s]+\s+(called|stated|said|wrote|messaged|insulted|threatened)\b'
]

# Supplementary curated explicit phrases
BULLYING_PHRASES = [
    "idiot", "moron", "loser", "useless", "stupid", "fool", "dumbass", "imbecile",
    "you're worthless", "you are worthless", "nobody likes you", "you should quit", "you're stupid",
    "you are stupid", "you're pathetic", "you are pathetic", "pathetic loser", "pathetic student",
    "can't do anything right", "cannot do anything right", "useless student",
    "you are useless", "you're useless", "hopeless case", "waste of space", "you'll never succeed",
    "you will never succeed", "pathetic attempt", "pathetic effort", "complete failure", "don't belong here",
    "do not belong here", "dumb idea", "ridiculous question", "everyone hates you", "you're a joke",
    "you are a joke", "worthless contribution", "mental midget", "academic fraud", "incompetent fool",
    "should drop out", "drop out immediately", "quit immediately", "stupid question", "waste of time",
    "failure student", "not cut out for", "worst student", "total disaster", "get lost", "nobody wants you"
]

class BullyingDetector:
    """Cyberbullying Threat Detection Engine combining ML with Calibrated Multitier Rules and Severity Differentiation"""
    
    # Configured binary threshold for classifying an email as cyberbullying
    BULLYING_THRESHOLD = 0.50
    
    def __init__(self, model_dir=None):
        self.model_dir = model_dir or Config.MODEL_PATH
        os.makedirs(self.model_dir, exist_ok=True)
        self.preprocessor = TextPreprocessor()
        self.vectorizer = None
        self.model = None
        self.model_type = 'None'
        self.last_metrics = {}
        self.load_latest_model()

    def load_model_pair(self, model_path_or_filename, vectorizer_path_or_filename):
        """
        Atomically loads a model artifact and its paired vectorizer artifact.
        Validates artifact existence, structure, and feature dimension compatibility.
        """
        m_path = model_path_or_filename if os.path.isabs(model_path_or_filename) else os.path.join(self.model_dir, model_path_or_filename)
        v_path = vectorizer_path_or_filename if os.path.isabs(vectorizer_path_or_filename) else os.path.join(self.model_dir, vectorizer_path_or_filename)
        
        if not os.path.exists(m_path):
            raise FileNotFoundError(f"Model artifact not found: {m_path}")
        if not os.path.exists(v_path):
            raise FileNotFoundError(f"Paired vectorizer artifact not found: {v_path}")
            
        temp_model = joblib.load(m_path)
        temp_vectorizer = joblib.load(v_path)
        
        # Verify feature dimension compatibility
        n_model_features = None
        if hasattr(temp_model, 'n_features_in_'):
            n_model_features = temp_model.n_features_in_
        elif hasattr(temp_model, 'coef_'):
            n_model_features = temp_model.coef_.shape[1]
            
        if hasattr(temp_vectorizer, 'vocabulary_') and n_model_features is not None:
            n_vec_features = len(temp_vectorizer.vocabulary_)
            if n_vec_features != n_model_features:
                raise ValueError(
                    f"Feature dimension mismatch: Model expects {n_model_features} features, "
                    f"but Vectorizer produces {n_vec_features} features."
                )
                
        # Atomic assignment
        self.model = temp_model
        self.vectorizer = temp_vectorizer
        self.model_type = 'Hybrid'
        return True

    def load_latest_model(self):
        """Loads latest model and vectorizer atomically from disk."""
        model_path = os.path.join(self.model_dir, 'latest_model.joblib')
        vectorizer_path = os.path.join(self.model_dir, 'latest_vectorizer.joblib')
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            try:
                return self.load_model_pair(model_path, vectorizer_path)
            except Exception as e:
                print(f"[BullyingDetector] Failed to load latest model pair: {e}")
                self.model = None
                self.vectorizer = None
        return False

    def is_educational_or_quoted_context(self, text):
        """Determines whether abusive terms appear strictly inside educational, analytical, or formal complaint reporting context."""
        text_lower = text.lower()
        
        # 1. Educational / Linguistic study context
        for pattern in EDUCATIONAL_CONTEXT_PATTERNS:
            if re.search(pattern, text_lower):
                return True
                
        # 2. Formal Complaint / Incident Report context
        for pattern in REPORTING_CONTEXT_PATTERNS:
            if re.search(pattern, text_lower):
                # Verify that this is not a direct 1st-person sender assertion/attack
                is_direct_sender_assertion = bool(
                    re.search(r'\b(i\s+am|i\'m)\s+(reporting|filing)\b', text_lower) or
                    re.search(r'\bif\s+you\s+(file|submit|make)\s+a?\s*(complaint|report|grievance)\b', text_lower)
                )
                if not is_direct_sender_assertion:
                    return True
                    
        return False

    def rule_based_check(self, text):
        """Calibrated rule-based matching with generalized tiers, severity classification, adversarial normalization, and context sensitivity."""
        if not isinstance(text, str) or not text.strip():
            return [], 0.0, [], 'LOW'
            
        text_lower = text.lower().strip()
        # Internal adversarial normalization layer for evading patterns (spaced/dotted/leetspeak)
        norm_text = self.preprocessor.normalize_adversarial_text(text)
        
        matched_items = []
        
        # Check for educational / reporting context
        is_context_mitigated = self.is_educational_or_quoted_context(text_lower)

        # Helper to match patterns across both original lower text and normalized adversarial text
        def _match_pattern_group(patterns, is_tier_physical=False, is_tier_abuse=False):
            for pat, label, weight in patterns:
                found_orig = [m.group(0) for m in re.finditer(pat, text_lower)]
                found_norm = [m.group(0) for m in re.finditer(pat, norm_text)]
                found_all = found_orig + found_norm
                if found_all:
                    for match_str in found_all:
                        match_str = match_str.strip()
                        if match_str and not any(item['match'] == match_str for item in matched_items):
                            # High recall rule: Physical/violent threats are NEVER mitigated by context
                            effective_weight = weight if (is_tier_physical or not is_context_mitigated) else 0.20
                            matched_items.append({
                                'match': match_str,
                                'weight': effective_weight,
                                'category': label,
                                'is_physical': is_tier_physical,
                                'is_abuse': is_tier_abuse
                            })

        # 1. Tier 1: Explicit Physical Threats / Violent Intimidation
        _match_pattern_group(PHYSICAL_THREAT_PATTERNS, is_tier_physical=True)

        # 2. Tier 2: Severe Abusive Language & Hostile Profanity
        _match_pattern_group(SEVERE_ABUSIVE_PATTERNS, is_tier_abuse=True)

        # 2b. Tier 2b: Dehumanizing, Racial & Discriminatory Harassment
        _match_pattern_group(DEHUMANIZING_DISCRIMINATORY_PATTERNS, is_tier_abuse=True)

        # 3. Tier 3: Targeted Insults & Personal Degradation
        _match_pattern_group(TARGETED_INSULT_PATTERNS)

        # 4. Tier 4: Academic Hostility
        _match_pattern_group(ACADEMIC_HOSTILITY_PATTERNS)

        # 5. Supplementary Curated Bullying Phrases
        for phrase in BULLYING_PHRASES:
            phrase_pat = r'\b' + re.escape(phrase) + r'\b'
            if (re.search(phrase_pat, text_lower) or re.search(phrase_pat, norm_text)) and not any(item['match'] == phrase for item in matched_items):
                effective_weight = 0.58 if not is_context_mitigated else 0.20
                matched_items.append({
                    'match': phrase,
                    'weight': effective_weight,
                    'category': 'Direct Personal Insult',
                    'is_physical': False,
                    'is_abuse': False
                })

        # 6. Tier 5: Mild Profanity (only contributes if no higher tier matched)
        if not matched_items:
            _match_pattern_group(MILD_PROFANITY_PATTERNS)

        # Deduplicate overlapping substring and normalized token matches
        unique_items = []
        for item in sorted(matched_items, key=lambda x: len(x['match']), reverse=True):
            expanded_m = self.preprocessor.expand_contractions(item['match'].lower())
            m_norm = re.sub(r'[\s\'\.\-_’‘`]+', '', expanded_m)
            is_sub = False
            for u in unique_items:
                expanded_u = self.preprocessor.expand_contractions(u['match'].lower())
                u_norm = re.sub(r'[\s\'\.\-_’‘`]+', '', expanded_u)
                if m_norm in u_norm:
                    is_sub = True
                    break
            if not is_sub:
                unique_items.append(item)

        unique_matches = [item['match'] for item in unique_items]
        unique_weights = [item['weight'] for item in unique_items]
        unique_categories = list(dict.fromkeys(item['category'] for item in unique_items))
        has_physical_threat = any(item['is_physical'] for item in unique_items)
        has_severe_abuse = any(item['is_abuse'] for item in unique_items)

        distinct_count = len(unique_items)
        is_only_mild_profanity = bool(unique_categories and all(cat == 'Mild / Colloquial Profanity' for cat in unique_categories))

        if distinct_count == 0:
            score = 0.0
            severity = 'LOW'
        else:
            if has_physical_threat:
                # Level 3: Threats / violence / violent word family -> CRITICAL
                score = round(max(0.92, max(unique_weights)), 3)
                severity = 'CRITICAL'
            elif has_severe_abuse or distinct_count >= 2 or any(w >= 0.70 for w in unique_weights):
                if is_context_mitigated and not has_severe_abuse:
                    score = 0.20
                    severity = 'LOW'
                else:
                    max_w = max(unique_weights) if unique_weights else 0.75
                    additional_boost = min(0.15, (distinct_count - 1) * 0.08) if distinct_count > 1 else 0.0
                    score = round(min(0.88, max(0.75, max_w + additional_boost)), 3)
                    severity = 'HIGH'
            elif is_context_mitigated:
                score = 0.20
                severity = 'LOW'
            elif is_only_mild_profanity:
                score = 0.20
                severity = 'LOW'
            else:
                score = 0.58
                severity = 'MEDIUM'
            
        return unique_matches, score, unique_categories, severity

    def predict(self, email_text, email_subject=""):
        """Runs the hybrid cyberbullying detection pipeline with separate detection and severity classification."""
        email_text = email_text or ""
        email_subject = email_subject or ""
        full_content = f"{email_subject}\n{email_text}".strip() if email_subject else email_text.strip()

        if not full_content:
            return {
                'is_bullying': False,
                'confidence': 0.0,
                'severity': 'LOW',
                'rule_based_matches': [],
                'rule_based_score': 0.0,
                'matched_categories': [],
                'ml_prediction': False,
                'ml_confidence': 0.0,
                'model_used': self.model_type,
                'combined_score': 0.0,
                'top_features': []
            }
            
        # 1. Rule-based check
        rule_matches, rule_score, matched_categories, severity = self.rule_based_check(full_content)
        
        # 2. ML Prediction (if model loaded)
        ml_pred = False
        ml_prob = 0.0
        top_features = []
        
        if self.model and self.vectorizer:
            try:
                clean_t = self.preprocessor.clean_text(email_text)
                if clean_t:
                    vec = self.vectorizer.transform([clean_t])
                    ml_pred = bool(self.model.predict(vec)[0])
                    if hasattr(self.model, 'predict_proba'):
                        ml_prob = float(self.model.predict_proba(vec)[0][1])
                    else:
                        ml_prob = 1.0 if ml_pred else 0.0
                        
                    # Extract top contributing features if relevant
                    if ml_prob >= 0.40:
                        top_features = self._extract_contributing_words(clean_t)
            except Exception as e:
                print(f"[BullyingDetector] Prediction error: {e}")
                ml_prob = 0.0
                
        # 3. Decision Fusion & Binary Classification Thresholding
        if rule_score >= self.BULLYING_THRESHOLD:
            # Rule detected single insult, multiple insults, severe abuse, or threat
            is_bullying = True
            combined_score = max(rule_score, round((rule_score * 0.6) + (ml_prob * 0.4), 3))
            if severity == 'MEDIUM' and combined_score >= 0.70:
                combined_score = 0.68
            final_confidence = round(max(combined_score, rule_score), 3)
        elif self.model and self.vectorizer:
            combined_score = round((rule_score * 0.4) + (ml_prob * 0.6), 3)
            if rule_score > 0 and combined_score >= self.BULLYING_THRESHOLD:
                is_bullying = True
                final_confidence = combined_score
                severity = 'MEDIUM' if severity == 'LOW' else severity
            elif rule_score == 0 and ml_prob >= 0.75:
                # High-certainty statistical ML classification
                is_bullying = True
                final_confidence = ml_prob
                severity = 'HIGH' if ml_prob >= 0.85 else 'MEDIUM'
            else:
                # Clean or borderline academic email below threshold
                is_bullying = False
                final_confidence = combined_score
                severity = 'LOW'
        else:
            is_bullying = False
            combined_score = rule_score
            final_confidence = rule_score
            severity = 'LOW'

        return {
            'is_bullying': bool(is_bullying),
            'confidence': final_confidence,
            'severity': severity,
            'rule_based_matches': rule_matches,
            'rule_based_score': round(rule_score, 3),
            'matched_categories': matched_categories,
            'ml_prediction': bool(ml_pred),
            'ml_confidence': round(ml_prob, 3),
            'model_used': self.model_type if self.model else 'Rule-Based Engine',
            'combined_score': round(combined_score, 3),
            'top_features': top_features
        }

    def _extract_contributing_words(self, clean_text):
        """Extracts top words in the email that have high TF-IDF / model weights."""
        if not self.model or not self.vectorizer or not hasattr(self.model, 'coef_'):
            return []
        try:
            words = clean_text.split()
            feature_names = np.array(self.vectorizer.get_feature_names_out())
            coefs = self.model.coef_[0]
            
            top_words = []
            for w in words:
                idx = np.where(feature_names == w)[0]
                if len(idx) > 0 and coefs[idx[0]] > 0.1:
                    top_words.append({'word': w, 'weight': round(float(coefs[idx[0]]), 3)})
                    
            top_words.sort(key=lambda x: x['weight'], reverse=True)
            return top_words[:5]
        except Exception:
            return []

    def train_model(self, emails, labels, model_type='logistic', test_size=0.25, is_synthetic=True):
        """Trains a new classifier and calculates proper test evaluation metrics including Confusion Matrix."""
        # Clean emails using adversarial-aware preprocessing
        cleaned_emails = [self.preprocessor.clean_text(e) for e in emails]
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            cleaned_emails, labels, test_size=test_size, random_state=42, stratify=labels
        )
        
        # Vectorize
        self.vectorizer = TfidfVectorizer(max_features=4000, ngram_range=(1, 2), min_df=1)
        X_train_vec = self.vectorizer.fit_transform(X_train)
        X_test_vec = self.vectorizer.transform(X_test)
        
        # Initialize model
        if model_type.lower() == 'svm':
            self.model = SVC(kernel='linear', probability=True, random_state=42)
            self.model_type = 'Support Vector Machine (SVM)'
        else:
            self.model = LogisticRegression(random_state=42, max_iter=1000)
            self.model_type = 'Logistic Regression'
            
        # Fit
        self.model.fit(X_train_vec, y_train)
        
        # Evaluate on Test Split
        y_pred = self.model.predict(X_test_vec)
        
        acc = round(accuracy_score(y_test, y_pred), 3)
        prec = round(precision_score(y_test, y_pred, zero_division=0), 3)
        rec = round(recall_score(y_test, y_pred, zero_division=0), 3)
        f1 = round(f1_score(y_test, y_pred, zero_division=0), 3)
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        self.last_metrics = {
            'model_type': self.model_type,
            'accuracy': acc,
            'precision': prec,
            'recall': rec,
            'f1_score': f1,
            'confusion_matrix': cm,
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'evaluation_type': 'Synthetic Benchmark' if is_synthetic else 'Real-World Validation Dataset',
            'evaluation_notice': (
                "Metrics generated from synthetic training benchmarks represent controlled scenario performance. "
                "Real-world generalization varies with noisy unseen emails."
            )
        }
        
        # Save atomic model + vectorizer pair to disk
        self.save_model()
        return self.last_metrics

    def save_model(self):
        """Serializes the current model and vectorizer atomically to disk."""
        if not self.model or not self.vectorizer:
            return False
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_name = self.model_type.replace(' ', '_').replace('(', '').replace(')', '')
        
        model_file = f"{model_name}_{timestamp}.joblib"
        vec_file = f"vectorizer_{timestamp}.joblib"
        
        joblib.dump(self.model, os.path.join(self.model_dir, model_file))
        joblib.dump(self.vectorizer, os.path.join(self.model_dir, vec_file))
        
        # Save pointers to latest atomically
        joblib.dump(self.model, os.path.join(self.model_dir, 'latest_model.joblib'))
        joblib.dump(self.vectorizer, os.path.join(self.model_dir, 'latest_vectorizer.joblib'))
        return True
