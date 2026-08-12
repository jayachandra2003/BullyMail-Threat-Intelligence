import pytest
from bullymail.services.bullying_detector import BullyingDetector
from bullymail.services.phishing_detector import PhishingDetector
from bullymail.services.risk_engine import UnifiedRiskEngine
from bullymail.services.preprocessor import TextPreprocessor

# =============================================================================
# 1. FIX M-01: ACADEMIC HOSTILITY FALSE POSITIVE REGRESSION TESTS
# =============================================================================
def test_m01_administrative_criticism_not_bullying():
    detector = BullyingDetector()
    
    # 1. Authority Warning
    res1 = detector.predict("Your academic performance is unacceptable. You must improve before the next review.")
    assert res1['is_bullying'] is False, "Administrative performance warning should NOT be classified as bullying"
    assert res1['severity'] == 'LOW'
    
    # 2. Assignment standard feedback
    res2 = detector.predict("Your assignment does not meet the required standards. Please revise before resubmission.")
    assert res2['is_bullying'] is False
    
    # 3. Incomplete submission
    res3 = detector.predict("The submission is incomplete and must be revised.")
    assert res3['is_bullying'] is False
    
    # 4. Attendance threshold
    res4 = detector.predict("Your attendance is below the required threshold.")
    assert res4['is_bullying'] is False
    
    # 5. Implementation errors
    res5 = detector.predict("Your implementation contains several errors in algorithm step 3.")
    assert res5['is_bullying'] is False

def test_m01_genuine_hostile_academic_harassment_detected():
    detector = BullyingDetector()
    
    # 1. Hostile demeaning work
    res1 = detector.predict("Your work is garbage and you are useless.")
    assert res1['is_bullying'] is True
    assert res1['severity'] == 'HIGH'
    
    # 2. Targeted failure label
    res2 = detector.predict("You are a pathetic failure.")
    assert res2['is_bullying'] is True
    assert res2['severity'] in ('MEDIUM', 'HIGH')
    
    # 3. Gatekeeping & humiliation
    res3 = detector.predict("Everyone knows you are too stupid to pass.")
    assert res3['is_bullying'] is True
    assert res3['severity'] == 'HIGH'
    
    # 4. Hostile invalidation
    res4 = detector.predict("Stop embarrassing yourself with this pathetic work.")
    assert res4['is_bullying'] is True


# =============================================================================
# 2. FIX M-02: ADVERSARIAL TEXT NORMALIZATION REGRESSION TESTS
# =============================================================================
def test_m02_adversarial_evasion_variants_detected():
    detector = BullyingDetector()
    preprocessor = TextPreprocessor()
    
    # 1. Standard sentence
    res_std = detector.predict("You're an idiot.")
    assert res_std['is_bullying'] is True
    assert res_std['severity'] == 'MEDIUM'
    
    # 2. Spaced letters: "i d i o t"
    res_spaced = detector.predict("You're an i d i o t.")
    assert res_spaced['is_bullying'] is True, "Failed to detect spaced adversarial token 'i d i o t'"
    assert res_spaced['severity'] == 'MEDIUM'
    
    # 3. Punctuation-spaced: "i.d.i.o.t"
    res_dotted = detector.predict("You're an i.d.i.o.t.")
    assert res_dotted['is_bullying'] is True, "Failed to detect dotted adversarial token 'i.d.i.o.t'"
    assert res_dotted['severity'] == 'MEDIUM'
    
    # 4. Leetspeak: "idi0t"
    res_leet1 = detector.predict("You're an idi0t.")
    assert res_leet1['is_bullying'] is True, "Failed to detect leetspeak 'idi0t'"
    assert res_leet1['severity'] == 'MEDIUM'
    
    # 5. Leetspeak combined: "1di0t"
    res_leet2 = detector.predict("You're an 1di0t.")
    assert res_leet2['is_bullying'] is True
    
    # 6. Compound spaced insults: "u s e l e s s  l o s e r"
    res_comp = detector.predict("You are a u s e l e s s  l o s e r.")
    assert res_comp['is_bullying'] is True
    assert res_comp['severity'] == 'HIGH'

def test_m02_normal_academic_punctuation_not_falsely_flagged():
    detector = BullyingDetector()
    text = "Dr. J. Smith published a paper in Vol. 1.2.3 with Ph.D. students discussing e.g. Graph Algorithms."
    res = detector.predict(text)
    assert res['is_bullying'] is False
    assert res['severity'] == 'LOW'


# =============================================================================
# 3. FIX L-01: REPORTING & QUOTED CONTEXT REGRESSION TESTS
# =============================================================================
def test_l01_reporting_context_suppression():
    detector = BullyingDetector()
    
    # 1. Quoted in formal complaint
    res1 = detector.predict("The student wrote, 'You are an idiot,' in the complaint.")
    assert res1['is_bullying'] is False, "Attributed quote in complaint should not be classified as sender bullying"
    assert res1['severity'] == 'LOW'
    
    # 2. Third-party incident report
    res2 = detector.predict("The student reported that John called her an idiot.")
    assert res2['is_bullying'] is False
    assert res2['severity'] == 'LOW'
    
    # 3. According to incident report
    res3 = detector.predict("According to the incident report, the sender called the victim a useless moron.")
    assert res3['is_bullying'] is False
    assert res3['severity'] == 'LOW'

def test_l01_direct_sender_insult_in_complaint_remains_detected():
    detector = BullyingDetector()
    
    # Sender directly asserts insult
    res1 = detector.predict("John is an idiot. I am reporting this in a complaint.")
    assert res1['is_bullying'] is True, "Direct insult by sender must remain detected"
    
    # Threat combined with reporting mention
    res2 = detector.predict("You are an idiot. If you file an incident report, I will hurt you.")
    assert res2['is_bullying'] is True
    assert res2['severity'] == 'CRITICAL'


# =============================================================================
# 4. FIX L-02: INFORMATIONAL SECURITY ALERT MITIGATION REGRESSION TESTS
# =============================================================================
def test_l02_informational_security_alert_not_phishing():
    phish_detector = PhishingDetector()
    
    # 1. Standard Chrome sign-in notice with "no action is needed"
    text1 = "A new sign-in was detected on your account from Chrome on Windows. If this was you, no action is needed."
    res1 = phish_detector.analyze(text1)
    assert res1['risk_level'] == 'LOW', f"Expected LOW for informational notice, got {res1['risk_level']}"
    assert res1['confidence'] < 0.35
    
    # 2. Informational notice with "you can safely ignore"
    text2 = "Security Alert: Unusual sign-in location detected. If you recognize this activity, you can safely ignore this notification."
    res2 = phish_detector.analyze(text2)
    assert res2['risk_level'] == 'LOW'

def test_l02_genuine_phishing_attacks_remain_detected():
    phish_detector = PhishingDetector()
    
    # 1. Sign-in detected + immediate verification request
    text1 = "New sign-in detected. Verify your password immediately."
    res1 = phish_detector.analyze(text1)
    assert res1['risk_level'] in ('HIGH', 'CRITICAL')
    
    # 2. Suspicious activity + 24-hour urgency
    text2 = "Suspicious activity detected. Verify your password within 24 hours."
    res2 = phish_detector.analyze(text2)
    assert res2['risk_level'] in ('HIGH', 'CRITICAL')
    assert res2['confidence'] >= 0.75
    
    # 3. Account termination threat
    text3 = "Your account will be deleted unless you verify your password."
    res3 = phish_detector.analyze(text3)
    assert res3['risk_level'] in ('HIGH', 'CRITICAL')
    assert res3['confidence'] >= 0.75


# =============================================================================
# 5. PHASE 2B SPECIFIC REGRESSION TESTS (BOUND-04, CTX-REP-01, CTX-REP-02)
# =============================================================================
def test_phase2b_bound04_pathetic_literary_vs_targeted():
    detector = BullyingDetector()
    
    # Untargeted descriptive / literary uses (MUST be NOT DETECTED)
    assert detector.predict("The character in the tragedy had a pathetic flaw.")['is_bullying'] is False
    assert detector.predict("The novel discusses the pathetic fallacy.")['is_bullying'] is False
    assert detector.predict("The patient's condition was pathetic.")['is_bullying'] is False
    assert detector.predict("The historical situation was pathetic.")['is_bullying'] is False
    assert detector.predict("Researchers discuss pathetic fallacy in literature.")['is_bullying'] is False
    
    # Targeted personal attacks / work demeaning (MUST be DETECTED)
    assert detector.predict("You are pathetic.")['is_bullying'] is True
    assert detector.predict("She is pathetic.")['is_bullying'] is True
    assert detector.predict("He is pathetic.")['is_bullying'] is True
    assert detector.predict("That pathetic loser should leave.")['is_bullying'] is True
    assert detector.predict("Your work is pathetic.")['is_bullying'] is True
    assert detector.predict("That was a pathetic effort.")['is_bullying'] is True
    assert detector.predict("Stop being pathetic.")['is_bullying'] is True

def test_phase2b_ctx_rep01_document_subject_reporting():
    detector = BullyingDetector()
    
    # Document as subject reporting
    res1 = detector.predict("The complaint states that John called her an idiot.")
    assert res1['is_bullying'] is False, "Document reporting John called her an idiot should not be sender bullying"
    assert res1['severity'] == 'LOW'
    
    res2 = detector.predict("The report states that the student was called useless.")
    assert res2['is_bullying'] is False
    assert res2['severity'] == 'LOW'
    
    res3 = detector.predict("The grievance alleges that the instructor called him a moron.")
    assert res3['is_bullying'] is False
    assert res3['severity'] == 'LOW'

def test_phase2b_ctx_rep02_document_contains_quoted_abuse():
    detector = BullyingDetector()
    
    # Document contains quoted phrases
    res1 = detector.predict("The incident report contains the phrase 'you are useless'.")
    assert res1['is_bullying'] is False
    assert res1['severity'] == 'LOW'
    
    res2 = detector.predict("The report contains the words 'you are stupid'.")
    assert res2['is_bullying'] is False
    assert res2['severity'] == 'LOW'
    
    res3 = detector.predict("The complaint quotes the sender saying 'you are an idiot'.")
    assert res3['is_bullying'] is False
    assert res3['severity'] == 'LOW'
    
    res4 = detector.predict("The document records the statement 'you are pathetic'.")
    assert res4['is_bullying'] is False
    assert res4['severity'] == 'LOW'

def test_phase2b_direct_attacks_with_complaint_words_preserved():
    detector = BullyingDetector()
    
    # Direct sender attack mentioning reporting
    assert detector.predict("John is an idiot. I am reporting this in a complaint.")['is_bullying'] is True
    assert detector.predict("John is an idiot. I am filing a complaint about him.")['is_bullying'] is True
    assert detector.predict("If you file a complaint, you are useless.")['is_bullying'] is True
    
    # Threat combined with complaint mention
    res_threat = detector.predict("You are an idiot. If you file an incident report, I will hurt you.")
    assert res_threat['is_bullying'] is True
    assert res_threat['severity'] == 'CRITICAL'
