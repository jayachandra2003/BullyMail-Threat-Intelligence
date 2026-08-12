import os
import pytest
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from bullymail.services.bullying_detector import BullyingDetector
from bullymail.services.preprocessor import TextPreprocessor
from bullymail.routes.datasets import (
    generate_synthetic_samples,
    BULLYING_TEMPLATES,
    CLEAN_NEUTRAL_TEMPLATES,
    COMMENDATION_POSITIVE_TEMPLATES
)

# =============================================================================
# 1. FIX 1: ATOMIC MODEL + VECTORIZER LOADING TESTS
# =============================================================================
def test_atomic_load_valid_pair_success(tmp_path):
    detector = BullyingDetector(model_dir=str(tmp_path))
    
    # Create matching model and vectorizer
    vec = TfidfVectorizer(max_features=50)
    X = vec.fit_transform(["you are an idiot", "welcome to class", "your work is useless", "office hours tomorrow"])
    y = [1, 0, 1, 0]
    
    clf = LogisticRegression()
    clf.fit(X, y)
    
    m_path = os.path.join(tmp_path, "model_test.joblib")
    v_path = os.path.join(tmp_path, "vec_test.joblib")
    joblib.dump(clf, m_path)
    joblib.dump(vec, v_path)
    
    # Should load atomically
    res = detector.load_model_pair(m_path, v_path)
    assert res is True
    assert detector.model is not None
    assert detector.vectorizer is not None

def test_atomic_load_missing_vectorizer_fails_safely(tmp_path):
    detector = BullyingDetector(model_dir=str(tmp_path))
    
    clf = LogisticRegression()
    m_path = os.path.join(tmp_path, "model_test.joblib")
    v_path = os.path.join(tmp_path, "nonexistent_vec.joblib")
    joblib.dump(clf, m_path)
    
    with pytest.raises(FileNotFoundError):
        detector.load_model_pair(m_path, v_path)

def test_atomic_load_missing_model_fails_safely(tmp_path):
    detector = BullyingDetector(model_dir=str(tmp_path))
    
    vec = TfidfVectorizer()
    vec.fit(["hello world"])
    m_path = os.path.join(tmp_path, "nonexistent_model.joblib")
    v_path = os.path.join(tmp_path, "vec_test.joblib")
    joblib.dump(vec, v_path)
    
    with pytest.raises(FileNotFoundError):
        detector.load_model_pair(m_path, v_path)

def test_atomic_load_feature_dimension_mismatch_rejected_safely(tmp_path):
    detector = BullyingDetector(model_dir=str(tmp_path))
    
    # Vectorizer with 10 features
    vec10 = TfidfVectorizer(max_features=10)
    X10 = vec10.fit_transform(["a b c d e f g h i j k l m n o p q r s t"])
    
    # Model trained on 10 features
    clf10 = LogisticRegression()
    clf10.fit(X10, [0])
    
    # Vectorizer with 20 features
    vec20 = TfidfVectorizer(max_features=20)
    vec20.fit(["a b c d e f g h i j k l m n o p q r s t u v w x y z"])
    
    m_path = os.path.join(tmp_path, "model_10.joblib")
    v_path = os.path.join(tmp_path, "vec_20.joblib")
    joblib.dump(clf10, m_path)
    joblib.dump(vec20, v_path)
    
    # Loading mismatched pair MUST raise ValueError and reject
    with pytest.raises(ValueError) as excinfo:
        detector.load_model_pair(m_path, v_path)
    assert "Feature dimension mismatch" in str(excinfo.value)

def test_atomic_load_latest_pair():
    detector = BullyingDetector()
    success = detector.load_latest_model()
    assert success is True
    assert detector.model is not None
    assert detector.vectorizer is not None


# =============================================================================
# 2. FIX 2: SYNTHETIC DATASET DIVERSITY & DEDUPLICATION TESTS
# =============================================================================
def test_dataset_diversity_template_counts():
    assert len(BULLYING_TEMPLATES) >= 20, f"Expected >= 20 bullying templates, got {len(BULLYING_TEMPLATES)}"
    assert len(CLEAN_NEUTRAL_TEMPLATES) >= 20, f"Expected >= 20 clean neutral templates, got {len(CLEAN_NEUTRAL_TEMPLATES)}"
    assert len(COMMENDATION_POSITIVE_TEMPLATES) >= 20, f"Expected >= 20 commendation templates, got {len(COMMENDATION_POSITIVE_TEMPLATES)}"

def test_dataset_deduplication_removes_duplicates():
    emails, labels, telemetry = generate_synthetic_samples(1000)
    
    assert len(emails) == 1000
    assert len(labels) == 1000
    assert telemetry['unique_rows'] == 1000
    
    # Verify zero exact duplicates in generated 1000 samples
    unique_exact = set(e.strip().lower() for e in emails)
    assert len(unique_exact) == len(emails), "Generated dataset should contain 0 exact duplicates"


# =============================================================================
# 3. FIX 3: ADVERSARIAL FEATURE REPRESENTATION IN ML PREPROCESSING
# =============================================================================
def test_adversarial_feature_representation_spaced():
    preprocessor = TextPreprocessor()
    
    cleaned_std = preprocessor.clean_text("You are an idiot.")
    cleaned_spaced = preprocessor.clean_text("You are an i d i o t.")
    cleaned_dotted = preprocessor.clean_text("You are an i.d.i.o.t.")
    cleaned_leet = preprocessor.clean_text("You are an idi0t.")
    
    # All adversarial representations should yield "idiot" token for ML vectorization
    assert "idiot" in cleaned_std.split()
    assert "idiot" in cleaned_spaced.split(), f"Expected 'idiot' in cleaned spaced text, got: {cleaned_spaced}"
    assert "idiot" in cleaned_dotted.split(), f"Expected 'idiot' in cleaned dotted text, got: {cleaned_dotted}"
    assert "idiot" in cleaned_leet.split(), f"Expected 'idiot' in cleaned leetspeak text, got: {cleaned_leet}"

def test_adversarial_feature_representation_benign_preserved():
    preprocessor = TextPreprocessor()
    
    cleaned_benign = preprocessor.clean_text("Dr. J. Smith published a paper in Vol. 1.2.3.")
    assert "idiot" not in cleaned_benign
    assert "useless" not in cleaned_benign
    assert "paper" in cleaned_benign
