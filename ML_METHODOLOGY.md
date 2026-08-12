# BullyMail V2 — Machine Learning & Threat Detection Methodology

## 1. Natural Language Processing Pipeline

BullyMail V2 implements an explainable NLP pipeline for textual threat classification:

1. **Contraction Expansion:** Normalizes informal text (`you're` $\rightarrow$ `you are`, `can't` $\rightarrow$ `cannot`) to maintain uniform vocabulary matching.
2. **Text Cleaning & Tokenization:** Strips irrelevant markup, isolates words, removes common English stopwords while preserving sentiment-bearing terms.
3. **TF-IDF Vectorization:**
   - Unigrams and Bigrams (`ngram_range=(1,2)`).
   - Maximum vocabulary size: 4,000 features.
   - Sublinear term frequency scaling.

---

## 2. Classification Models & Evaluation Metrics

BullyMail V2 supports two primary supervised classifiers:
- **Logistic Regression:** Provides smooth probability estimation and interpretable feature coefficients.
- **Support Vector Machine (Linear SVC with Platt Scaling):** Maximizes margin separation in high-dimensional TF-IDF space.

### Evaluation Metrics
To prevent metric distortion:
- Performance is evaluated using a **stratified train/test split (75% train / 25% test)**.
- Metrics reported:
  - **Accuracy:** Overall proportion of correct predictions.
  - **Precision:** $\frac{TP}{TP + FP}$ — proportion of flagged emails that are genuinely hostile.
  - **Recall:** $\frac{TP}{TP + FN}$ — proportion of hostile emails successfully captured.
  - **F1-Score:** Harmonic mean of precision and recall.
  - **Confusion Matrix:** Explicit breakdown of True Positives (TP), True Negatives (TN), False Positives (FP), and False Negatives (FN).

> [!NOTE]
> Metrics evaluated against synthetic benchmark datasets reflect controlled scenario performance. Real-world email streams are handled via the hybrid combination of ML probabilities and calibrated heuristic rule engines.

---

## 3. Calibrated Rule-Based Heuristic

Rather than arbitrary linear phrase counts, BullyMail V2 uses an exponential saturation formula for rule matching:
$$\text{Rule Score} = 1.0 - e^{-0.6 \times N_{\text{matches}}}$$

- 1 matched hostile phrase $\rightarrow \approx 0.45$ score.
- 2 matched hostile phrases $\rightarrow \approx 0.70$ score.
- 3 matched hostile phrases $\rightarrow \approx 0.83$ score.
- 4+ matched hostile phrases $\rightarrow \ge 0.90$ score.

---

## 4. Explainable AI (XAI) Token Contribution

For any ML prediction, the system extracts the highest-weighted positive coefficients from the trained model that intersect with tokens present in the email, explaining **why** the model triggered.
