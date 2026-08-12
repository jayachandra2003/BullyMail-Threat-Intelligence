import pytest
from bullymail.services.bullying_detector import BullyingDetector

def test_bullying_detection_positive():
    detector = BullyingDetector()
    text = "Your submission is a complete failure and you're worthless. You are a useless student."
    result = detector.predict(text)
    
    assert result['is_bullying'] is True
    assert len(result['rule_based_matches']) >= 2
    assert result['confidence'] >= 0.50
    assert result['rule_based_score'] >= 0.50

def test_bullying_detection_negative():
    detector = BullyingDetector()
    text = "Great job on the research proposal. Your methodology is clear and well-structured."
    result = detector.predict(text)
    
    assert result['is_bullying'] is False
    assert len(result['rule_based_matches']) == 0
    assert result['confidence'] < 0.50

# 1. Lexical Insult Variants (Case, Punctuation, Whitespace, Standalone vs Sentence)
def test_insult_lexical_variants():
    detector = BullyingDetector()
    
    # Standalone lowercase
    r1 = detector.predict("idiot")
    assert r1['is_bullying'] is True
    assert r1['severity'] == 'MEDIUM'
    assert 'idiot' in r1['rule_based_matches']
    
    # Uppercase with punctuation
    r2 = detector.predict("IDIOT!")
    assert r2['is_bullying'] is True
    assert r2['severity'] == 'MEDIUM'
    assert 'idiot' in r2['rule_based_matches']
    
    # Surrounding whitespace
    r3 = detector.predict("   idiot   ")
    assert r3['is_bullying'] is True
    assert r3['severity'] == 'MEDIUM'
    
    # Full sentence
    r4 = detector.predict("You are an idiot.")
    assert r4['is_bullying'] is True
    assert r4['severity'] == 'MEDIUM'
    
    # Sentence with uppercase insult
    r5 = detector.predict("you are an IDIOT")
    assert r5['is_bullying'] is True
    assert r5['severity'] == 'MEDIUM'

# 2. Single Insult -> DETECTED, MEDIUM
def test_regression_1_single_insult_detected_medium():
    detector = BullyingDetector()
    single_insult_samples = [
        "idiot",
        "IDIOT!",
        "stupid",
        "moron",
        "fool",
        "loser",
        "useless",
        "pathetic",
        "dumb",
        "imbecile",
        "You are an idiot.",
        "You are stupid.",
        "You are a moron.",
        "You are useless.",
        "You are pathetic."
    ]
    for sample in single_insult_samples:
        res = detector.predict(sample)
        assert res['is_bullying'] is True, f"Failed detection for: {sample}"
        assert res['severity'] == 'MEDIUM', f"Expected MEDIUM severity for single insult: {sample}, got {res['severity']}"
        assert res['confidence'] >= 0.50
        assert res['confidence'] < 0.70

# 3. Multiple Insults / Harassment -> DETECTED, HIGH
def test_regression_2_multiple_insults_detected_high():
    detector = BullyingDetector()
    
    # Insults in compound sentence
    res1 = detector.predict("You are an idiot and a moron.")
    assert res1['is_bullying'] is True
    assert res1['severity'] == 'HIGH'
    assert res1['confidence'] >= 0.70
    
    # Insults with social exclusion
    res2 = detector.predict("You are an idiot and everyone hates you. You should leave the course.")
    assert res2['is_bullying'] is True
    assert res2['severity'] == 'HIGH'
    assert res2['confidence'] >= 0.70

# 4. Threat + Insult -> DETECTED, CRITICAL
def test_regression_3_threat_and_insult_detected_critical():
    detector = BullyingDetector()
    sample = "You are an idiot. I will hurt you."
    res = detector.predict(sample)
    
    assert res['is_bullying'] is True
    assert res['severity'] == 'CRITICAL'
    assert res['confidence'] >= 0.88

# 5. Clean Academic Email -> NOT DETECTED, LOW
def test_regression_4_clean_academic_email_not_detected_low():
    detector = BullyingDetector()
    sample = "Dear Students, the guidelines for Assignment 2 on Graph Algorithms have been posted on the portal. Office hours are on Thursday at 2 PM."
    res = detector.predict(sample)
    
    assert res['is_bullying'] is False
    assert res['severity'] == 'LOW'
    assert len(res['rule_based_matches']) == 0
    assert res['rule_based_score'] == 0.0
    assert res['confidence'] < 0.50

# Severe Profanity Directive
def test_regression_severe_profanity_detected():
    detector = BullyingDetector()
    res1 = detector.predict("motherfucker")
    assert res1['is_bullying'] is True
    assert res1['severity'] in ('HIGH', 'CRITICAL')
    assert res1['confidence'] >= 0.70
    
    res2 = detector.predict("Shut the fuck up you piece of shit.")
    assert res2['is_bullying'] is True
    assert res2['severity'] in ('HIGH', 'CRITICAL')
    assert res2['confidence'] >= 0.75

# Educational discussion mentioning profanity -> NOT DETECTED
def test_regression_educational_discussion_mentioning_profanity_not_detected():
    detector = BullyingDetector()
    text = "In our linguistics seminar, we analyzed the etymology of taboo words including 'fuck' and 'damn' across historical texts."
    result = detector.predict(text)
    
    assert result['is_bullying'] is False
    assert result['severity'] == 'LOW'
    assert result['confidence'] < 0.50

# Mild isolated profanity without target -> NOT DETECTED
def test_regression_mild_isolated_profanity_without_target_not_detected():
    detector = BullyingDetector()
    text = "Damn, that was a tough exam, but I hope the grading curve helps."
    result = detector.predict(text)
    
    assert result['is_bullying'] is False
    assert result['severity'] == 'LOW'
    assert result['confidence'] < 0.50

def test_train_and_evaluate_metrics():
    detector = BullyingDetector()
    emails = [
        "You are worthless and a complete failure",
        "Useless student, you should drop out",
        "Nobody likes you and your work is pathetic",
        "Great work on your thesis, excellent progress",
        "Thank you for submitting your assignment on time",
        "The department seminar is scheduled for 3 PM"
    ]
    labels = [1, 1, 1, 0, 0, 0]
    
    metrics = detector.train_model(emails, labels, model_type='logistic', test_size=0.33)
    
    assert 'accuracy' in metrics
    assert 'precision' in metrics
    assert 'recall' in metrics
    assert 'f1_score' in metrics
    assert 'confusion_matrix' in metrics
    assert isinstance(metrics['confusion_matrix'], list)
