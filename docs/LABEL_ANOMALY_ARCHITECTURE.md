# AIVARA — Label Anomaly & Confident Learning Architecture Specification
## Phase 5.5.1: Architecture Review & Design Freeze

**Version:** 1.0.0-frozen  
**Status:** DESIGN FROZEN (Implementation Target: Phase 5.5)  
**Security Classification:** Local / Air-Gapped Assurance Engine  
**Target Sub-System:** Phase 5.5 — Label Anomaly & Confident Learning Detection Engine (LADE)  

---

## 1. Scope & Objective

The **Label Anomaly & Confident Learning Detection Engine (LADE)** identifies statistical inconsistencies between observed dataset annotations and visual feature representations in contributed computer vision datasets.

### Core Principle: LABEL ANOMALY ≠ MALICIOUSNESS
Label noise, ambivalence, and classification errors occur routinely in real-world computer vision datasets due to human annotator fatigue, ambiguous visual boundaries, occlusions, and ontology overlap.
- The LADE identifies **statistical discrepancies, out-of-fold predictive disagreements, and confident learning noise estimates**.
- The LADE **NEVER** asserts "malicious intent", "contributor sabotage", or "poisoning attacks".
- Semantic risk attribution is exclusively performed downstream by the Contributor Risk Engine (Phase 5.8) and Executive Risk Engine (Phase 8).

```
                     Canonical Dataset Manifest
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
      Classification Dataset           Object Detection Dataset
      (ImageFolder / Single-Label)      (Bounding Box Label Audit)
                 │                               │
                 └───────────────┬───────────────┘
                                 │
                   Offline Model Feature Extractor
                   (Frozen Pretrained / Cached Embeddings)
                                 │
                                 ▼
                   Stratified K-Fold CV Splitter
                  (Deterministic Seed, No Leakage)
                                 │
                                 ▼
                     Out-of-Fold Probabilities
                      P(y = k | x) for all x
                                 │
                                 ▼
                    Confident Learning Engine
                    - Class-specific thresholds (t_j)
                    - Joint Distribution Matrix Q(y_tilde, y*)
                    - Noise Transition Matrix
                                 │
                                 ▼
                   Label Anomaly Scoring & Margin
                                 │
                                 ▼
                 Structured Evidence & Findings
                 (ADR-028 evidence_layer="detection")
```

---

## 2. Supported Annotation Types

| Modality / Format | Phase 5.5 Support | Operational Strategy |
| :--- | :--- | :--- |
| **ImageFolder Classification** | **Full Support** | Evaluates global image label $\tilde{y}$ against out-of-fold visual predictions $\hat{P}(y \mid x)$. |
| **COCO / YOLO Object Detection (Class Labels)** | **Full Support** | Crops bounding box regions of interest (RoIs) or evaluates localized box class labels against localized feature representations. |
| **Bounding Box Coordinates ($[x, y, w, h]$)** | **Deferred (Phase 5.7)** | Spatial bounding box degradation and jitter detection belong to Image Quality / Box Anomaly analysis. |
| **Dense Segmentation Masks** | **Unsupported** | Marked as `UNSUPPORTED / UNVERIFIABLE`. |
| **Continuous Regression Targets** | **Unsupported** | Marked as `UNSUPPORTED / UNVERIFIABLE`. |

---

## 3. Statistical Formulation

Let the dataset $\mathcal{D} = \{(x_n, \tilde{y}_n)\}_{n=1}^N$ consist of $N$ image samples, where:
- $x_n \in \mathcal{X}$ is the visual input representation (raw image or frozen feature embedding).
- $\tilde{y}_n \in \{1, \dots, K\}$ is the **observed (given) label** in the dataset metadata.
- $y_n^* \in \{1, \dots, K\}$ is the **unobserved latent true label** (an inferred statistical quantity, NOT ground truth).
- $\hat{P}(y = k \mid x_n) = \hat{p}_{n, k}$ is the out-of-fold predicted probability distribution over the $K$ classes such that $\sum_{k=1}^K \hat{p}_{n, k} = 1.0$.

### Joint Noise Distribution Matrix $\mathbf{Q}_{\tilde{y}, y^*}$
AIVARA estimates the $K \times K$ joint distribution matrix $Q_{i, j} = P(\tilde{y} = i, y^* = j)$, representing the joint probability that a sample is labeled as class $i$ when its latent true class is estimated to be $j$.

---

## 4. Confident Learning Architecture

AIVARA implements the foundational principles of Confident Learning (Northcutt et al.) to estimate label noise without assuming pristine ground truth.

### 4.1 Class-Specific Confident Thresholds ($t_j$)
Instead of using an arbitrary fixed probability threshold (such as $0.5$), AIVARA computes an empirical expected confidence threshold for each class $j \in \{1, \dots, K\}$:

$$t_j = \frac{1}{|\mathcal{X}_{\tilde{y}=j}|} \sum_{x \in \mathcal{X}_{\tilde{y}=j}} \hat{P}(y = j \mid x)$$

where $\mathcal{X}_{\tilde{y}=j} = \{x_n : \tilde{y}_n = j\}$ is the subset of samples observed with label $j$.

### 4.2 Confident Count Matrix ($C_{i, j}$)
A sample $x_n$ with observed label $\tilde{y}_n = i$ is assigned to latent class $y_n^* = j$ if and only if:
1. The model's out-of-fold probability for class $j$ exceeds its class threshold: $\hat{P}(y = j \mid x_n) \ge t_j$.
2. Class $j$ is the maximum threshold-normalized candidate:
   $$j = \arg\max_{k \in \{1, \dots, K\}} \left( \hat{P}(y = k \mid x_n) - t_k \right)$$

The unnormalized integer count matrix $C_{i, j}$ records the total samples labeled $i$ that meet the confident threshold for latent class $j$:
$$C_{i, j} = \left| \{ x_n : \tilde{y}_n = i \text{ and } y_n^* = j \} \right|$$

### 4.3 Normalized Joint Distribution Estimation ($\hat{Q}_{i, j}$)
$$\hat{Q}_{i, j} = \frac{\frac{C_{i, j}}{\sum_{i'=1}^K C_{i', j}} \cdot |\mathcal{X}_{\tilde{y}=j}|}{N}$$

---

## 5. Out-of-Fold Prediction Strategy

To eliminate training data leakage, predictions for sample $x_n$ MUST NEVER be generated by a model trained on $(x_n, \tilde{y}_n)$.

```
Dataset (N Samples)
  ├── Fold 1 ──> Held out (Predicted by Model trained on Folds 2,3,4,5)
  ├── Fold 2 ──> Held out (Predicted by Model trained on Folds 1,3,4,5)
  ├── Fold 3 ──> Held out (Predicted by Model trained on Folds 1,2,4,5)
  ├── Fold 4 ──> Held out (Predicted by Model trained on Folds 1,2,3,5)
  └── Fold 5 ──> Held out (Predicted by Model trained on Folds 1,2,3,4)
```

### Invariants for Cross-Validation:
- **Number of Folds ($K$):** Default $K = 5$ stratified folds.
- **Stratification:** Folds maintain exact class proportions of $\tilde{y}$.
- **Deterministic Partitioning:** Folds are assigned using SHA-256 of `sample_id` + `dataset_hash` + fixed random seed (`seed=42`).
- **Minimum Class Representation:** Classes with $< 5$ samples cannot be split across 5 folds and are treated under rare-class guardrails.

---

## 6. Operational Interpretation of "NO BASELINE RETRAINING"

The project charter specifies: **NO BASELINE RETRAINING**.

### What This Constraint Prohibits:
1. AIVARA **never** modifies, retrains, fine-tunes, or mutates the customer's production model or submitted baseline checkpoints.
2. AIVARA **never** executes multi-epoch backpropagation on deep convolutional/transformer neural network weights.

### What This Constraint Authorizes:
1. **Frozen Offline Feature Extraction:** Utilizing pre-cached, offline feature extractors (e.g. frozen MobileNet-v3, ResNet-50, or DINOv2 backbones in inference-only `eval()` mode) to compute fixed visual feature vectors.
2. **Temporary Lightweight Estimators:** Fitting closed-form or fast convex classifiers (e.g. Ridge Regression, Stratified Linear Logistic Regression, or Nearest Centroid Classifiers) on top of the frozen embeddings solely to compute out-of-fold probability vectors $\hat{P}(y \mid x)$ for confident learning.
3. **Precomputed Prediction Ingestion:** Utilizing existing precomputed inference probabilities if supplied with the dataset manifest.

---

## 7. Offline Model Availability & State Machine

In strict air-gapped environments where feature extraction models may be disabled or unavailable, the engine follows an explicit state machine:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Model Availability Resolver                           │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
         [ Model Present ]                               [ Model Absent ]
                 │                                               │
         Check Checksum / Format                         Return Status:
                 │                                      MODEL_UNAVAILABLE
                 ├── Incompatible -> MODEL_INCOMPATIBLE          │
                 ├── Load Failed  -> MODEL_LOAD_FAILED           │
                 ▼                                               ▼
          MODEL_AVAILABLE                          Emit Finding: INSUFFICIENT_EVIDENCE
                 │                                       (Confidence: 0.0)
                 ▼                                               │
       Execute Out-of-Fold                             Zero Fabricated Scores
       Confident Learning                                        │
                 │                                               ▼
                 └───────────────────────┬───────────────────────┘
                                         │
                                         ▼
                             Structured Finding Models
```

---

## 8. Probability Calibration & Anomaly Scoring

### 8.1 Confident Margin ($\text{Margin}_n$)
For sample $x_n$ with observed label $\tilde{y}_n = i$, let $j^* = \arg\max_{j \ne i} \hat{P}(y = j \mid x_n)$ be the highest-probability alternative class.

$$\text{Margin}_n = \left( \hat{P}(y = j^* \mid x_n) - t_{j^*} \right) - \left( \hat{P}(y = i \mid x_n) - t_i \right)$$

- $\text{Margin}_n > 0$: Strong evidence that sample $x_n$ belongs to latent class $j^*$ rather than observed class $i$.
- $\text{Margin}_n \le 0$: Insufficient statistical discrepancy to dispute observed label $i$.

### 8.2 Normalized Anomaly Score ($S_n \in [0.0, 1.0]$)
$$S_n = \frac{1}{1 + e^{-5 \cdot \text{Margin}_n}}$$

### 8.3 Finding Confidence ($\text{Conf}_n \in [0.0, 1.0]$)
Confidence measures statistical reliability, incorporating class sample size $|\mathcal{X}_{\tilde{y}}|$ and out-of-fold probability certainty:
$$\text{Conf}_n = \min\left(1.0, \frac{|\mathcal{X}_{\tilde{y}_n}|}{20}\right) \cdot \left( \hat{P}(y = j^* \mid x_n) \right)$$

---

## 9. Small Dataset & Rare Class Guardrails

| Sample Count ($N$) | Behavior & Classification |
| :--- | :--- |
| **$N < 25$ total samples** | Confident learning is skipped. All samples marked `INSUFFICIENT_EVIDENCE` (`confidence=0.0`). |
| **Class count $< 5$ samples** | Class cannot support 5-fold cross-validation. Marked `RARE_CLASS_ANOMALY` with confidence discounted by $50\%$. |
| **Singleton Class ($N=1$)** | Cannot be partitioned into train/test folds. Marked `UNVERIFIABLE`. |
| **Severe Class Imbalance ($> 50:1$)** | Normalized count matrix $\hat{Q}_{i, j}$ applies inverse class frequency weighting to prevent dominant classes from masking minority noise. |

---

## 10. Taxonomic Anomaly Categories

Every finding generated by LADE is classified into an explicit category:

1. **`POSSIBLE_LABEL_MISMATCH`:** Sample's visual features strongly align with alternative class $j^*$ exceeding its confident threshold ($\text{Margin} > 0$).
2. **`HIGH_CONFIDENCE_ALTERNATIVE_CLASS`:** Alternative class probability $\hat{P}(y = j^* \mid x) > 0.85$ while observed class probability $< 0.15$.
3. **`CLASS_SYSTEMATIC_ANOMALY`:** Widespread reciprocal confusion between class $i$ and class $j$ affecting $> 15\%$ of class $i$ samples.
4. **`RARE_CLASS_ANOMALY`:** Potential anomaly detected in a low-sample class ($< 10$ samples), tagged with lower statistical confidence.
5. **`MODEL_DISAGREEMENT`:** Weak anomaly where alternative class probability marginally exceeds observed label without meeting confident threshold.
6. **`INSUFFICIENT_EVIDENCE`:** Dataset size or class distribution is statistically inadequate for reliable estimation.
7. **`MODEL_UNAVAILABLE`:** Feature extraction model is missing or incompatible in the air-gapped environment.

---

## 11. Domain Schema & Finding Representation

```python
class LabelAnomalyCategory(str, Enum):
    POSSIBLE_LABEL_MISMATCH = "possible_label_mismatch"
    HIGH_CONFIDENCE_ALTERNATIVE_CLASS = "high_confidence_alternative_class"
    CLASS_SYSTEMATIC_ANOMALY = "class_systematic_anomaly"
    RARE_CLASS_ANOMALY = "rare_class_anomaly"
    MODEL_DISAGREEMENT = "model_disagreement"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    MODEL_UNAVAILABLE = "model_unavailable"

class LabelPrediction(BaseModel):
    model_config = ConfigDict(frozen=True)
    sample_id: str
    relative_path: str
    observed_category_id: int
    observed_category_name: str
    predicted_category_id: int
    predicted_category_name: str
    probabilities: Dict[str, float]
    is_out_of_fold: bool = True

class LabelAnomalyFinding(BaseModel):
    model_config = ConfigDict(frozen=True)
    finding_id: str
    sample_id: str
    relative_path: str
    observed_category_id: int
    observed_category_name: str
    suggested_category_id: Optional[int] = None
    suggested_category_name: Optional[str] = None
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    category: LabelAnomalyCategory
    margin: float
    evidence_layer: str = "detection"  # ADR-028 compliance
    model_id: Optional[str] = None
    model_hash: Optional[str] = None
    contributors: Tuple[str, ...] = Field(default_factory=tuple)
    limitations: List[str] = Field(default_factory=list)

class LabelAnomalyScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    total_samples: int
    evaluated_samples: int
    anomalous_samples_count: int
    joint_distribution_matrix: List[List[float]]
    class_thresholds: Dict[str, float]
    findings: Tuple[LabelAnomalyFinding, ...]
    warnings: List[str] = Field(default_factory=list)
    capability_info: Dict[str, Any] = Field(default_factory=dict)
```

---

## 12. Security Threat Model

| Threat / Attack Vector | System Resilience & Mitigation |
| :--- | :--- |
| **Adversarial Label Flipping** | Confident Learning computes class-specific thresholds, identifying flipped samples as high-margin anomalies. |
| **Data Leakage in CV** | Stratified $K$-fold partitioning enforces strict isolation between training and evaluation folds. |
| **Model Weight Manipulation** | Model identity and feature weights are hashed with SHA-256 (`model_hash`) and verified against tampering. |
| **Class Imbalance Poisoning** | Normalized joint probability estimation $\hat{Q}_{i, j}$ prevents minority class anomalies from being drowned by majority priors. |
| **Decompression / Memory DOS** | Feature vectors are extracted in streaming batches ($500$ samples) with immediate buffer deallocation. |

---

## 13. Phase 4 & Database Integration Design

- **Database Persistence (Zero Schema Migrations):**
  - Findings map directly to `FindingModel` with `evidence_layer="detection"`, `finding_type="LABEL_ANOMALY"`, `severity="medium"`, `disposition="review"`.
  - Evidence payloads map to `EvidenceModel` containing $\hat{P}(y \mid x)$ and $\text{Margin}$.
- **Phase 4 Cryptographic Provenance (Design Only):**
  - Future Phase 5.9 binds `dataset_hash`, `model_hash`, `class_thresholds_hash`, and finding summaries to a signed `ProvenanceRecordModel`.

---

## 14. Phase 5.5 Implementation Roadmap

- **Sub-Phase 5.5.2:** Implement `backend/aivara/dataset/anomalies/schemas.py` and `exceptions.py`.
- **Sub-Phase 5.5.3:** Implement `backend/aivara/dataset/anomalies/folds.py` (Deterministic stratified $K$-fold partitioner).
- **Sub-Phase 5.5.4:** Implement `backend/aivara/dataset/anomalies/confident_learning.py` (Thresholds, count matrix, joint distribution).
- **Sub-Phase 5.5.5:** Implement `backend/aivara/dataset/anomalies/estimator.py` (Out-of-fold probabilistic classifier on frozen features).
- **Sub-Phase 5.5.6:** Implement `backend/aivara/dataset/anomalies/detector.py` (LADE orchestrator).
- **Sub-Phase 5.5.7:** Build comprehensive unit and adversarial test suite `tests/test_label_anomalies.py`.
