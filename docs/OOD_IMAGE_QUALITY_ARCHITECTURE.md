# AIVARA — Out-of-Distribution (OOD) & Image Quality Architecture Specification
## Phase 5.7.1: Architecture Review & Design Freeze

**Version:** 1.0.0-frozen  
**Status:** DESIGN FROZEN (Implementation Target: Phase 5.7)  
**Security Classification:** Local / Air-Gapped Assurance Engine  
**Target Sub-System:** Phase 5.7 — OOD & Image Quality Analysis Engine (OQAE)  
**Evidence Layer:** `evidence_layer="detection"` (ADR-028 compliant)

---

## 1. Executive Summary & Scope

The **Out-of-Distribution (OOD) & Image Quality Analysis Engine (OQAE)** is an offline, air-gapped statistical audit sub-system designed to:
1. Objectively quantify **image quality characteristics and degradation** across visual dataset samples.
2. Detect **out-of-distribution (OOD) samples and systematic distribution shifts** relative to an established reference distribution or internal dataset baseline.
3. Identify operational dataset drift stemming from physical, environmental, or acquisition factors (e.g., sensor variability, seasonal changes, day/night illumination, geographic terrain).

```
                        CanonicalDatasetManifest (Phase 5.2)
                                       │
                     ┌─────────────────┴─────────────────┐
                     ▼                                   ▼
        ┌─────────────────────────┐         ┌─────────────────────────┐
        │  Deterministic Image    │         │  Dual Feature Extractor │
        │  Quality Analysis (IQA) │         │  (Pixel Stats + Vision) │
        │                         │         │                         │
        │ - Laplacian Blur        │         │ - Luminance/Chroma      │
        │ - Dynamic Range/Exposure│         │ - Texture & Color Hists │
        │ - Spatial Noise & SNR   │         │ - Lightweight Embedding │
        │ - JPEG Blockiness (PSNR)│         │   (Frozen / Offline)    │
        │ - Aspect/Resolution     │         │                         │
        └────────────┬────────────┘         └────────────┬────────────┘
                     │                                   │
                     │                      ┌────────────┴────────────┐
                     │                      ▼                         ▼
                     │             ┌─────────────────┐       ┌─────────────────┐
                     │             │ Global / Local  │       │ Subgroup/Domain │
                     │             │ kNN/Mahalanobis │       │ Shift (MMD /    │
                     │             │ Distance Model  │       │ Energy Distance)│
                     │             └────────┬────────┘       └────────┬────────┘
                     │                      │                         │
                     ▼                      ▼                         ▼
            ┌─────────────────────────────────────────────────────────────┐
            │                 Phase 5.7 Finding Synthesis                 │
            │                                                             │
            │   - Independent Quality & OOD Evidence Generation           │
            │   - Robust Non-Parametric Threshold Calibration (MAD/IQR)   │
            │   - Small-Data Guardrails & Model Availability Safeguards   │
            │   - evidence_layer="detection"                              │
            └──────────────────────────────┬──────────────────────────────┘
                                           │
                        Structured Immutable Findings
                                           │
             ┌─────────────────────────────┴─────────────────────────────┐
             ▼                                                           ▼
    Phase 5.8 Contributor Risk                                  Phase 8 Executive Risk
```

### Foundational Semantic Invariants

```
   ┌──────────────────────────────────────────────────────────────────────────┐
   │                                                                          │
   │   OOD ≠ MALICIOUSNESS                                                    │
   │   IMAGE QUALITY DEGRADATION ≠ MALICIOUSNESS                              │
   │   DISTRIBUTION SHIFT ≠ ATTACK                                            │
   │   OPERATIONAL DRIFT ≠ DATA POISONING                                     │
   │                                                                          │
   └──────────────────────────────────────────────────────────────────────────┘
```

1. **Strictly Observational:** The engine produces objective statistical and physical measurements under `evidence_layer="detection"`.
2. **Zero Attribution of Intent:** The engine **NEVER** asserts "malicious intent", "poisoning attack", "tampering", "adversarial perturbation", "sabotage", or "contributor guilt".
3. **Multi-Signal Independence:** Image quality degradation, out-of-distribution distance, and label anomalies are strictly orthogonal signals. An image may be high-quality yet OOD (e.g., a pristine photo of a rare desert terrain in a forest dataset) or low-quality yet in-distribution (e.g., motion-blurred standard urban traffic).
4. **No Baseline Retraining:** The engine evaluates frozen visual representations and non-parametric reference distributions without modifying or retraining downstream customer models.

---

## 2. Supported Modalities & Analytical Scope

| Modality / Format | Support Status | Operational Scope |
| :--- | :--- | :--- |
| **ImageFolder Classification** | **Full Support** | Global image-level quality analysis, full-frame feature extraction, global/local OOD scoring, and dataset-level distribution shift. |
| **COCO / YOLO Object Detection (Full Frame)** | **Full Support** | Evaluates overall image acquisition quality, scene illumination, and background/context distribution shift. |
| **COCO / YOLO Object Detection (Bounding-Box Crops)** | **Supported (Secondary)** | Evaluates localized visual quality and sub-region OOD distance for isolated bounding-box crops ($[x, y, w, h]$). |
| **Spatial Coordinate Jitter / Box Drift** | **Unsupported** | Geometric box displacement without pixel analysis belongs to downstream annotation geometry audits. |
| **Dense Segmentation Masks** | **Unsupported** | Marked as `UNSUPPORTED / UNVERIFIABLE`. |
| **Continuous Regression Targets** | **Unsupported** | Marked as `UNSUPPORTED / UNVERIFIABLE`. |

---

## 3. Image Quality Analysis (IQA) Architecture

Image quality analysis operates deterministically directly on decoded pixel arrays ($H \times W \times C$ RGB uint8/float32) without requiring heavy neural networks.

### 3.1 Objective Metric Formulations

#### 1. Blur & Defocus (Variance of Laplacian)
Let $I_{\text{gray}}(x, y) = 0.299 R + 0.587 G + 0.114 B$. The discrete Laplacian operator $\nabla^2 I_{\text{gray}}$ is computed using the standard $3 \times 3$ kernel:
$$\mathbf{L} = \begin{bmatrix} 0 & 1 & 0 \\ 1 & -4 & 1 \\ 0 & 1 & 0 \end{bmatrix}, \quad \text{BlurScore} = \text{Var}\left( I_{\text{gray}} * \mathbf{L} \right)$$
- **Interpretation:** Lower variance indicates low high-frequency edge energy (motion blur or optical defocus). High variance indicates crisp edges or high-frequency noise.
- **Range:** $[0.0, \infty)$. Clean images typically $> 100.0$; heavy blur $< 25.0$.

#### 2. Sharpness & High-Frequency Acutance
Measured via normalized Tenengrad gradient magnitude:
$$\text{Tenengrad} = \frac{1}{H \cdot W} \sum_{x, y} \left( G_x(x, y)^2 + G_y(x, y)^2 \right)$$
where $G_x, G_y$ are horizontal and vertical Sobel filter responses.

#### 3. Exposure & Luminance Distribution
Let $Y \in [0, 255]$ be the luminance channel.
- **Mean Luminance:** $\mu_Y = \frac{1}{HW} \sum_{x,y} Y(x,y)$
- **Underexposure Fraction ($F_{\text{under}}$):** Proportion of pixels with $Y(x,y) < 15$ ($< 6\%$).
- **Overexposure / Saturation Clipping Fraction ($F_{\text{over}}$):** Proportion of pixels with $Y(x,y) > 240$ ($> 94\%$).
- **Dynamic Range / Contrast:** $\text{Contrast}_{\text{RMS}} = \sqrt{\frac{1}{HW} \sum_{x,y} (Y(x,y) - \mu_Y)^2}$.

#### 4. Color Cast & Saturation
- In HSV space, mean saturation $\mu_S = \frac{1}{HW} \sum S(x,y)$.
- Color balance is measured via the chromaticity divergence in CIELAB space:
  $$\Delta_{\text{cast}} = \sqrt{\mu_{a^*}^2 + \mu_{b^*}^2}$$

#### 5. Spatial Noise & Local Variance Estimation
Estimated using the Immerkaer fast noise variance estimation algorithm (robust to image edges):
$$\sigma_{\text{noise}}^2 = \frac{\pi}{2} \frac{1}{6(W-2)(H-2)} \sum_{x,y} \left| (I * \mathbf{N})(x,y) \right|$$
where $\mathbf{N} = \begin{bmatrix} 1 & -2 & 1 \\ -2 & 4 & -2 \\ 1 & -2 & 1 \end{bmatrix}$.
- **Signal-to-Noise Ratio (SNR):** $\text{SNR}_{\text{dB}} = 20 \log_{10}\left( \frac{\mu_Y}{\sigma_{\text{noise}} + \epsilon} \right)$.

#### 6. Compression Artifacts & Blockiness (JPEG Blocking Metric)
Evaluates 8x8 block boundary discontinuities in the DCT luminance grid:
$$\text{Blockiness} = \frac{\sum_{\text{block edges}} |Y(x, y) - Y(x+1, y)|}{\sum_{\text{non-edges}} |Y(x, y) - Y(x+1, y)| + \epsilon}$$
- **Interpretation:** Values significantly $> 1.0$ indicate visible 8x8 grid boundary steps from aggressive lossy compression.

#### 7. Structural Integrity & Extreme Dimensions
- **Resolution:** $H \times W$, Total Pixels $N_{\text{pix}} = H \cdot W$.
- **Aspect Ratio:** $\text{AR} = \frac{W}{H}$.
- **Uniform Region Fraction:** Percentage of $16 \times 16$ non-overlapping patches with variance $\sigma_{\text{patch}}^2 < 1.0$ (detects synthetic padding, occluded camera sensors, or corrupt decoding).

---

## 4. OOD & Distribution Shift Architecture

### 4.1 Feature Representation Strategy: Dual-Tier Architecture

To guarantee 100% offline, air-gapped execution on limited hardware (CPU or 6GB GPU), Phase 5.7 uses a dual-tier representation:

```
                  ┌──────────────────────────────────────────────┐
                  │           Input Sample Image (RGB)           │
                  └──────────────────────┬───────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
   ┌───────────────────────────┐                   ┌───────────────────────────┐
   │  Tier 1: Statistical      │                   │  Tier 2: Semantic Visual  │
   │  Pixel Descriptor         │                   │  Embeddings               │
   │  (Always Available)       │                   │  (When Model Available)   │
   │                           │                   │                           │
   │ - 32-bin Color Histograms │                   │ - Frozen Pretrained CNN / │
   │ - Spatial Pyramid Moments │                   │   Vision Transformer      │
   │ - Haralick Texture Stats  │                   │ - Offline Weights Only    │
   │ - Dimension: D = 128      │                   │ - Dimension: D = 512/768  │
   └─────────────┬─────────────┘                   └─────────────┬─────────────┘
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         │
                         Unified Feature Vector z in R^D
```

1. **Tier 1 (Deterministic Statistical Descriptor — Always Active):**
   - Combines normalized RGB/HSV histograms, local binary pattern (LBP) texture summaries, and multiscale spatial luminance moments.
   - Guaranteed $O(N)$ CPU execution, zero external model dependency, zero download requirement.
2. **Tier 2 (Semantic Deep Embedding — Active when model available):**
   - Utilizes frozen, offline pretrained feature extractors (e.g., standard ResNet-50 / MobileNetV3 / lightweight ViT).
   - If offline weights are missing or incompatible, the engine cleanly degrades to Tier 1 without failing or fabricating embeddings (`feature_status="TIER1_FALLBACK"`).

### 4.2 Reference Distribution Establishment

An OOD score is meaningless without a well-defined reference distribution $\mathcal{D}_{\text{ref}}$. AIVARA supports three operational reference modes:

```
Reference Modes:
1. INTERNAL_DATASET_BASELINE (Default)
   - Splits dataset into deterministic folds or uses the entire curated dataset as its own baseline.
   - Identifies internal distribution outliers and subgroup anomalies.

2. EXPLICIT_REFERENCE_DATASET
   - Compares an untrusted contribution batch against a cryptographically verified reference dataset manifest (Phase 5.3).

3. FROZEN_DOMAIN_REFERENCE
   - Pre-computed centroid and covariance statistics from domain-calibrated golden datasets.
```

If $|\mathcal{D}_{\text{ref}}| < 25$, the engine triggers the **Small Reference Guardrail**, returning `INSUFFICIENT_SUPPORT` and preventing uncalibrated OOD declarations.

### 4.3 OOD Scoring Formulations

#### 1. Global OOD: Normalized $k$-Nearest Neighbor ($k\text{NN}$) Distance
For a query sample feature $\mathbf{z}_q$ and reference set $\mathcal{Z}_{\text{ref}} = \{\mathbf{z}_1, \dots, \mathbf{z}_M\}$:
1. Compute pairwise normalized Euclidean or Cosine distances:
   $$d(\mathbf{z}_q, \mathbf{z}_i) = 1 - \frac{\mathbf{z}_q \cdot \mathbf{z}_i}{\|\mathbf{z}_q\| \|\mathbf{z}_i\|}$$
2. Find the $k$ nearest reference neighbors ($k = \min(10, \lfloor \sqrt{M} \rfloor)$).
3. The raw $k\text{NN}$ OOD score is the average distance to the $k$ nearest neighbors:
   $$\text{Score}_{\text{kNN}}(\mathbf{z}_q) = \frac{1}{k} \sum_{j=1}^k d_{(j)}(\mathbf{z}_q)$$

#### 2. Local & Class-Conditional OOD
To avoid penalizing legitimate multimodal class diversity (e.g., a "snowmobile" image naturally differing from a "sports car" image in a vehicle dataset):
- For a sample with observed class $c$, evaluate distance against the class-specific reference subset $\mathcal{Z}_{\text{ref}}^{(c)} = \{\mathbf{z}_i \in \mathcal{Z}_{\text{ref}} \mid y_i = c\}$:
  $$\text{Score}_{\text{class-kNN}}(\mathbf{z}_q) = \frac{1}{k_c} \sum_{j=1}^{k_c} d_{(j)}^{(c)}(\mathbf{z}_q)$$
- **Guardrail:** If $|\mathcal{Z}_{\text{ref}}^{(c)}| < 5$, fallback to Global $k\text{NN}$ and flag `subgroup_support="INSUFFICIENT_CLASS_SUPPORT"`.

#### 3. Subgroup & Dataset-Level Distribution Shift
To detect systemic environmental drift (e.g., day vs. night, summer vs. winter, Sensor A vs. Sensor B) across a batch or contributor contribution:
- **Maximum Mean Discrepancy (MMD):**
  $$\text{MMD}^2(\mathcal{Z}_{\text{query}}, \mathcal{Z}_{\text{ref}}) = \frac{1}{N^2} \sum_{i,j} \mathcal{K}(\mathbf{z}_i, \mathbf{z}_j) + \frac{1}{M^2} \sum_{i,j} \mathcal{K}(\mathbf{x}_i, \mathbf{x}_j) - \frac{2}{NM} \sum_{i,j} \mathcal{K}(\mathbf{z}_i, \mathbf{x}_j)$$
  where $\mathcal{K}(\mathbf{u}, \mathbf{v}) = \exp\left(-\gamma \|\mathbf{u} - \mathbf{v}\|^2\right)$ is a deterministic multi-scale RBF kernel.
- **Energy Distance:** A non-parametric distribution divergence metric robust to high dimensionality.

---

## 5. Threshold Calibration & Non-Parametric Safeguards

Universal static magic numbers are strictly forbidden for OOD scoring. Thresholds are calibrated dynamically from the reference distribution using robust non-parametric order statistics.

```
                    Reference Distance Distribution
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
    Median Distance (M_d)                      Median Absolute Deviation (MAD)
              │                                         │
              └────────────────────┬────────────────────┘
                                   │
                     Threshold = M_d + beta * MAD
                          (beta = 3.0 or 4.5)
```

### 5.1 Median Absolute Deviation (MAD) Calibration
For reference score distribution $\mathcal{S}_{\text{ref}} = \{s_1, \dots, s_M\}$:
1. $\text{Median}(\mathcal{S}) = \tilde{s}$
2. $\text{MAD} = \text{Median}\left( \{ |s_i - \tilde{s}| \}_{i=1}^M \right)$
3. **Conservative OOD Threshold:** $\tau_{\text{OOD}} = \tilde{s} + 3.5 \cdot (1.4826 \cdot \text{MAD})$
4. **Extreme OOD Threshold:** $\tau_{\text{extreme}} = \tilde{s} + 5.0 \cdot (1.4826 \cdot \text{MAD})$

### 5.2 Wilson Score Uncertainty for Anomaly Rates
When reporting the proportion $\hat{p}$ of anomalous images in a batch of size $N$, the engine computes the 95% Wilson confidence lower bound $w^-(p, N)$ to prevent small batches from generating inflated confidence scores.

---

## 6. Small-Data, Rare-Class & Missing Data Guardrails

| Condition | Threshold | Engine Behavior | Output Status |
| :--- | :--- | :--- | :--- |
| **Micro-Dataset** | $N < 25$ | Bypasses complex distribution shift; computes only basic deterministic IQA. | `INSUFFICIENT_EVIDENCE` / `SMALL_DATASET_GUARDRAIL` |
| **Tiny Reference Set** | $M_{\text{ref}} < 25$ | Declares reference distribution inadequate for OOD calibration. | `UNVERIFIABLE` / `INSUFFICIENT_REFERENCE_SUPPORT` |
| **Rare Class Subgroup** | $N_c < 5$ | Disables class-conditional OOD; evaluates global distance only with caveat. | `FALLBACK_GLOBAL_OOD` |
| **Singleton Class** | $N_c = 1$ | Skips subgroup OOD; records singleton status. | `UNVERIFIABLE_CLASS_OOD` |
| **Model Unavailable** | Weights Missing | Activates Tier 1 deterministic statistical descriptor fallback. | `FEATURE_EXTRACTOR_UNAVAILABLE` (Tier 1 Fallback) |
| **Corrupted Image** | Decode Error | Flags corruption immediately without crashing the scan pipeline. | `IMAGE_CORRUPTION` |
| **Decompression Bomb** | Pixels $> 10^8$ or Aspect $> 100$ | Rejects image defensively via Phase 5.2 security validator. | `SECURITY_VALIDATION_FAILED` |

---

## 7. Model-Bias & Environmental Drift Separation

```
                  Observed Distribution Divergence
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
Legitimate Operational Drift                      Concentrated Anomaly Pattern
- Broad, consistent shift across many samples    - High concentration in single contributor
- Natural environmental variation                - Disjoint from visual acquisition physics
  (e.g., winter snow, night-time IR sensor)      - Accompanied by severe quality corruption
- Uniform within acquisition subgroup            - Isolated cluster of synthetic artifacts
         │                                                 │
         ▼                                                 ▼
evidence_category=                                evidence_category=
"OPERATIONAL_DISTRIBUTION_SHIFT"                  "ANOMALOUS_DISTRIBUTION_CLUSTER"
(is_drift=True, is_targeted=False)                (is_drift=False, is_targeted=True)
```

The engine explicitly decouples legitimate domain shifts from targeted anomalies:
1. **Environmental Cluster Validation:** If a group of OOD samples share coherent metadata (e.g., timestamp range, camera model, consistent low-light luminance), the finding is classified as `OPERATIONAL_DISTRIBUTION_SHIFT`.
2. **Model Bias Documentation:** Pretrained embedding models are known to have domain biases (e.g., ImageNet models overemphasizing texture over shape). Tier 1 physical features are always reported alongside embeddings to cross-validate findings.

---

## 8. Evidence Taxonomy

All engine findings are mapped to a structured, strongly-typed taxonomy:

| Category | Description | Primary Evidence Source |
| :--- | :--- | :--- |
| `IMAGE_CORRUPTION` | Unreadable, header-damaged, or truncated image payload. | Pixel Decoder / Integrity Check |
| `BLUR_ANOMALY` | Severe optical defocus or motion blur. | Variance of Laplacian $< \tau_{\text{blur}}$ |
| `EXPOSURE_UNDEREXPOSED` | Substantial loss of shadow detail / black clipping. | Luminance $F_{\text{under}} > 0.40$ |
| `EXPOSURE_OVEREXPOSED` | Blown-out highlights / white saturation clipping. | Luminance $F_{\text{over}} > 0.30$ |
| `NOISE_ANOMALY` | Unusually high high-frequency sensor noise. | Immerkaer Noise Variance $> \tau_{\text{noise}}$ |
| `COMPRESSION_BLOCKINESS` | Severe 8x8 DCT grid blocking artifacts. | JPEG Blockiness Metric $> \tau_{\text{block}}$ |
| `RESOLUTION_ANOMALY` | Unusually low resolution or extreme aspect ratio. | Pixel Dimensions $(H, W)$ |
| `COLOR_CAST_ANOMALY` | Extreme monochromatic tint or unnatural saturation. | CIELAB $\Delta_{\text{cast}}$, HSV Saturation |
| `GLOBAL_OOD` | Sample distance exceeds calibrated reference threshold. | $k\text{NN}$ Distance $> \tau_{\text{OOD}}$ |
| `LOCAL_SUBGROUP_OOD` | Sample is anomalous within its specific class/domain. | Class-Conditional $k\text{NN}$ Distance |
| `OPERATIONAL_DISTRIBUTION_SHIFT`| Systematic dataset-wide environmental/sensor shift. | MMD / Energy Distance $> \tau_{\text{shift}}$ |
| `INSUFFICIENT_EVIDENCE` | Dataset or reference size too small for statistical validity. | Guardrail Check ($N < 25$) |
| `UNVERIFIABLE` | Modality or missing baseline precludes verification. | Support / Modality Check |
| `FEATURE_EXTRACTOR_UNAVAILABLE`| Deep extractor weights unavailable (Tier 1 used). | Model State Machine |

---

## 9. Immutable Domain Models

All data transfer objects and analytical structures are strictly immutable Pydantic models (`frozen=True`):

```python
from enum import Enum
from typing import Dict, Any, Tuple, Optional, List
from pydantic import BaseModel, ConfigDict, Field

class FeatureExtractionStatus(str, Enum):
    TIER1_STATISTICAL_ONLY = "tier1_statistical_only"
    TIER2_DEEP_EMBEDDING = "tier2_deep_embedding"
    FEATURE_EXTRACTOR_UNAVAILABLE = "feature_extractor_unavailable"
    FEATURE_EXTRACTOR_INCOMPATIBLE = "feature_extractor_incompatible"
    FEATURE_EXTRACTION_FAILED = "feature_extraction_failed"

class ImageQualityMetrics(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    blur_laplacian_var: float = Field(..., ge=0.0, description="Variance of Laplacian")
    sharpness_tenengrad: float = Field(..., ge=0.0, description="Tenengrad gradient sharpness")
    mean_luminance: float = Field(..., ge=0.0, le=255.0, description="Mean pixel luminance")
    rms_contrast: float = Field(..., ge=0.0, description="RMS contrast")
    underexposure_ratio: float = Field(..., ge=0.0, le=1.0, description="Fraction of clipped dark pixels")
    overexposure_ratio: float = Field(..., ge=0.0, le=1.0, description="Fraction of clipped bright pixels")
    mean_saturation: float = Field(..., ge=0.0, le=1.0, description="Mean HSV saturation")
    color_cast_delta: float = Field(..., ge=0.0, description="CIELAB chromaticity divergence")
    noise_variance: float = Field(..., ge=0.0, description="Estimated spatial noise variance")
    snr_db: float = Field(..., description="Estimated Signal-to-Noise Ratio in dB")
    jpeg_blockiness: float = Field(..., ge=0.0, description="JPEG 8x8 block boundary step ratio")
    width: int = Field(..., ge=1, description="Pixel width")
    height: int = Field(..., ge=1, description="Pixel height")
    aspect_ratio: float = Field(..., gt=0.0, description="Width / Height aspect ratio")
    uniform_region_ratio: float = Field(..., ge=0.0, le=1.0, description="Fraction of uniform zero-variance patches")
    composite_quality_score: float = Field(..., ge=0.0, le=1.0, description="Calibrated quality index (1.0 = pristine)")

class OODScore(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    global_knn_distance: float = Field(..., ge=0.0, description="Average distance to k nearest global neighbors")
    local_class_knn_distance: Optional[float] = Field(default=None, ge=0.0, description="Distance to class-specific neighbors")
    is_global_ood: bool = Field(..., description="Whether global distance exceeds calibrated threshold")
    is_local_ood: Optional[bool] = Field(default=None, description="Whether class distance exceeds threshold")
    calibrated_threshold: float = Field(..., ge=0.0, description="MAD-calibrated reference threshold")
    normalized_novelty_score: float = Field(..., ge=0.0, le=1.0, description="Calibrated OOD novelty index")
    nearest_reference_sample_ids: Tuple[str, ...] = Field(default_factory=tuple)

class DistributionShiftEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    mmd_statistic: float = Field(..., ge=0.0, description="Maximum Mean Discrepancy against reference")
    energy_distance: float = Field(..., ge=0.0, description="Energy distance between sample and reference sets")
    is_shift_detected: bool = Field(..., description="Whether shift metric exceeds permutation-test threshold")
    p_value_estimate: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Permutation test p-value")
    affected_sample_count: int = Field(..., ge=0)
    primary_shift_factors: Tuple[str, ...] = Field(default_factory=tuple, description="Identified shift axes (e.g. luminance, blur)")

class OODScanFinding(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    finding_id: str = Field(..., min_length=1)
    sample_id: str = Field(..., min_length=1)
    annotation_id: Optional[str] = Field(default=None)
    category: str = Field(..., description="Category from evidence taxonomy")
    evidence_layer: str = Field(default="detection")
    severity: str = Field(default="LOW", description="LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(..., ge=0.0, le=1.0)
    quality_metrics: Optional[ImageQualityMetrics] = Field(default=None)
    ood_score: Optional[OODScore] = Field(default=None)
    explanation: str = Field(..., min_length=1)
    limitations: Tuple[str, ...] = Field(default_factory=tuple)

class OODScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    scan_id: str = Field(..., min_length=1)
    dataset_name: str = Field(..., min_length=1)
    dataset_fingerprint: str = Field(..., min_length=64, max_length=64)
    total_samples: int = Field(..., ge=0)
    scanned_samples: int = Field(..., ge=0)
    feature_extraction_status: FeatureExtractionStatus = Field(...)
    quality_anomaly_count: int = Field(..., ge=0)
    ood_sample_count: int = Field(..., ge=0)
    distribution_shift: Optional[DistributionShiftEvidence] = Field(default=None)
    findings: Tuple[OODScanFinding, ...] = Field(default_factory=tuple)
    diagnostics: Dict[str, Any] = Field(default_factory=dict)
```

---

## 10. Computational Complexity & Performance Budget

```
Target Workload: 100,000 images on standard commodity CPU (or optional 6GB GPU)
```

| Operation | Complexity | Optimization Strategy |
| :--- | :--- | :--- |
| **IQA Metric Extraction** | $\mathcal{O}(N \cdot H \cdot W)$ | Pure vectorized NumPy operations; parallelized across CPU worker pool. |
| **Tier 1 Feature Extraction** | $\mathcal{O}(N \cdot H \cdot W)$ | Single-pass spatial histogram binning. |
| **Tier 2 Embedding Extraction** | $\mathcal{O}(N)$ forward passes | Batched inference with PyTorch `no_grad()`; automatic mixed precision (FP16). |
| **$k\text{NN}$ Distance Calculation** | $\mathcal{O}(N \cdot M_{\text{ref}})$ naive | Fast vector dot product or spatial tree index; exact matrix multiplication $\mathbf{Z}_q \mathbf{Z}_{\text{ref}}^T$. |
| **MMD & Energy Distance** | $\mathcal{O}(N^2 + M^2)$ | Multi-scale subsampled kernel approximation ($\le 2,000$ points) for massive datasets. |

---

## 11. Comprehensive Testing Strategy (36 Scenarios)

The Phase 5.7 test suite will validate the following 36 dedicated scenarios:

1. **Blur Detection:** Severe optical and motion blur correctly flagged with low Laplacian variance.
2. **Sharp / High-Quality Image:** Clean, crisp images pass with high composite quality score.
3. **Severe Underexposure:** Black-clipped images identified via luminance histogram.
4. **Severe Overexposure:** White-saturated images identified without false-positive clipping.
5. **Noise Estimation:** Gaussian and Poisson sensor noise accurately measured via Immerkaer method.
6. **JPEG Compression Blockiness:** Heavy DCT blocking artifacts detected on recompressed images.
7. **Resolution Anomaly:** Extremely small ($< 32 \times 32$) or unexpected dimensions flagged.
8. **Extreme Aspect Ratios:** Panoramic or needle-like aspect ratios flagged under `ASPECT_RATIO_ANOMALY`.
9. **Color Cast Anomaly:** Strong monochromatic tint detected via CIELAB chromaticity divergence.
10. **Corrupted Image Handling:** Truncated/corrupted file payloads return structured `IMAGE_CORRUPTION` without engine crash.
11. **Uniform / Blank Images:** Solid color or blank images detected via uniform patch analysis.
12. **Global OOD Sample:** Visual outliers significantly distant from reference distribution correctly flagged.
13. **Local / Class-Conditional OOD:** Class-specific outlier correctly identified while respecting class multimodal distributions.
14. **In-Distribution Class Diversity:** Natural visual variation between distinct legitimate classes does not trigger false OOD flags.
15. **High Quality + OOD Independence:** Pristine, sharp image of unusual domain flagged as OOD but NOT quality-degraded.
16. **Low Quality + In-Distribution Independence:** Blurry/noisy image of standard domain flagged as quality-anomalous but NOT OOD.
17. **Legitimate Seasonal Shift:** Dataset-wide summer-to-winter shift flagged as `OPERATIONAL_DISTRIBUTION_SHIFT` with `is_targeted=False`.
18. **Sensor / Day-Night Shift:** Systematic luminance change across a batch correctly classified as operational drift.
19. **Class Imbalance Resilience:** Majority classes do not skew or dominate reference OOD thresholds.
20. **Micro-Dataset Guardrail ($N < 25$):** Small dataset triggers `INSUFFICIENT_EVIDENCE` gracefully.
21. **Tiny Reference Set Guardrail ($M_{\text{ref}} < 25$):** Insufficient reference data returns `INSUFFICIENT_REFERENCE_SUPPORT`.
22. **Rare Class Subgroup Guardrail ($N_c < 5$):** Falls back to global OOD distance when class sample size is inadequate.
23. **Singleton Class Subgroup:** Single-sample class handled without division-by-zero or crash.
24. **Feature Extractor Available:** Tier 2 deep embedding pipeline executes when weights are present.
25. **Feature Extractor Missing (Tier 1 Fallback):** Missing weights cleanly fall back to Tier 1 statistical descriptor.
26. **Feature Extractor Incompatible:** Dimensionality or architecture mismatch handled gracefully with structured diagnostic.
27. **Feature Extraction Failure:** Individual image failure in batch does not invalidate the entire dataset.
28. **Deterministic Reproducibility:** Identical inputs and seeds produce bit-exact identical metrics and findings.
29. **NaN / Inf / Zero-Division Protection:** Zero variance, flat images, and degenerate inputs handled safely.
30. **Decompression Bomb Defense:** Oversized images ($> 10^8$ pixels) rejected defensively.
31. **Multi-Signal Structured Output:** Simultaneous blur, noise, and OOD return distinct, uncollapsed evidence items.
32. **Contributor Association Preservation:** Contributor IDs preserved in finding metadata without computing contributor risk scores.
33. **Unsupported Modalities (Segmentation/Regression):** Non-classification/detection annotations return `UNVERIFIABLE`.
34. **Object Detection Bounding-Box RoI Crops:** Quality and OOD computed on cropped bounding box regions.
35. **Zero Malicious Language Invariant:** Complete audit of generated findings, explanations, and diagnostics for absence of malicious attribution words.
36. **Large-Scale Performance Benchmark:** 1,000+ sample synthetic dataset processes within memory and CPU time budget.

---

## 12. Explicit Non-Goals & Architectural Boundaries

1. **No Malicious Attribution:** The engine does not declare data poisoning, sabotage, attacker presence, or malicious intent.
2. **No Contributor Risk Scoring:** Final contributor risk aggregation belongs exclusively to Phase 5.8.
3. **No Cryptographic Provenance Binding:** Provenance binding of findings belongs to Phase 5.9.
4. **No Database Persistence:** Database schema modifications and ORM migrations are out of scope.
5. **No Network Operations:** No remote API calls, telemetry, or remote model downloads.
6. **No Spatial Bounding Box Jitter Analysis:** Geometric coordinate jitter is handled in annotation auditing.

---

## 13. Frozen Architectural Decisions

- **Dec-5.7-1:** Dual-tier feature extraction with guaranteed Tier 1 statistical fallback for 100% offline air-gapped execution.
- **Dec-5.7-2:** Non-parametric Median Absolute Deviation (MAD) calibration for all OOD thresholds; zero static magic thresholds.
- **Dec-5.7-3:** Strict separation of Image Quality, OOD Distance, and Label Anomaly evidence layers.
- **Dec-5.7-4:** Operational drift detection via non-parametric MMD and Energy Distance with `is_targeted=False` semantics.
- **Dec-5.7-5:** Small-data guardrails enforced at $N < 25$ and class subgroup support at $N_c < 5$.
- **Dec-5.7-6:** Zero Phase 4 cryptographic modifications and zero database schema modifications.
