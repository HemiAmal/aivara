# AIVARA — Dataset Integrity Engine Architecture Specification
## Phase 5.1: Architecture Review & Design Freeze

**Version:** 1.0.0-draft  
**Status:** DESIGN FROZEN (Implementation Not Started)  
**Security Classification:** Local / Air-Gapped Assurance Engine  
**Target Sub-System:** Phase 5 — Dataset Integrity Engine (DIE)  

---

## 1. Scope

The **Dataset Integrity Engine (DIE)** is the primary Layer 1 & Layer 2 analysis component of AIVARA responsible for evaluating the structural, statistical, visual, semantic, and cryptographic integrity of computer vision training and evaluation datasets.

### In-Scope Functional Capabilities
1. **Multi-Format Ingestion & Parsing:** Deterministic extraction and validation of computer vision datasets in standard formats:
   - COCO Object Detection / Segmentation (`instances_*.json`, `captions_*.json`, `person_keypoints_*.json`)
   - YOLO Object Detection / Segmentation (`dataset.yaml`, labels directory with `.txt` coordinates, image directory)
   - ImageFolder Classification (hierarchical directory structure: `class_name/image_xxx.ext`)
   - Common raster image formats: PNG, JPEG/JPG, WebP, BMP, TIFF
2. **Deterministic Dataset Normalization:** Converting diverse dataset layouts into an internal immutable canonical representation (`CanonicalSample`, `CanonicalAnnotation`, `CanonicalDatasetManifest`).
3. **Multi-Tiered Cryptographic & Perceptual Fingerprinting:**
   - **Dataset-Level:** Canonical Merkle Root and Manifest SHA-256 digest.
   - **Image-Level:** Content SHA-256 digest, raw pixel buffer hash, multiscale perceptual hashes (pHash / dHash).
   - **Annotation-Level:** Canonical JCS (RFC 8785) hash per bounding box/polygon/label tuple and composite annotation set hash.
4. **Adversarial & Statistical Detection Analyzers:**
   - **Label Anomaly Detection:** Identifying label-feature inconsistencies, noise, and ambivalence via confident learning / feature space outlier analysis.
   - **Targeted Label-Flipping Detection:** Identifying systematic class-to-class boundary perturbations and asymmetric label migration.
   - **Near-Duplicate Detection:** Identifying exact clones, rescaled/re-encoded images, cropped variants, and visual collisions using spatial indexing (BK-trees / VP-trees over Hamming distance) in sub-quadratic time.
   - **Out-of-Distribution (OOD) Detection:** Identifying domain drift, corrupted visual artifacts, synthetic noise, and cross-dataset contamination.
   - **Contributor-Level Aggregation:** Correlating label anomalies, flipping, near-duplicates, and metadata patterns to specific external annotators/sources.
5. **Structured Evidence Generation:** Generating traceable, immutable `Evidence` and `Finding` records adhering to the ADR-028 two-layer architecture.
6. **Air-Gapped & Graceful Degradation:** Full operational execution in 100% offline environments with modular feature fallback when deep feature extractors or embedding backends are disabled or unavailable.

---

## 2. Non-Goals

To maintain strict architectural boundaries and prevent scope creep, Phase 5 explicitly excludes:
1. **Model Training / Fine-Tuning / Retraining:** AIVARA never trains, retrains, fine-tunes, or modifies customer models.
2. **Dataset Mutation / Cleaning In-Place:** AIVARA does not alter, delete, crop, or overwrite customer dataset files on disk. Analysis is strictly read-only and non-destructive.
3. **Arbitrary Multimodal / NLP / Audio Ingestion:** Video streams, 3D point clouds, text corpora, and audio spectrograms are out of scope for Phase 5.
4. **Online Cloud APIs & Telemetry:** No external network lookups, cloud-based vision APIs, or third-party hosted inference services.
5. **Automated Maliciousness Attribution (Risk Decisioning):** The Dataset Integrity Engine emits *findings*, *evidence*, and *confidence scores*. It **does not** compute final holistic risk or determine executive disposition (`ACCEPT`, `REVIEW`, `QUARANTINE`); that responsibility belongs exclusively to the downstream **Risk Engine** (Phase 8).
6. **Live Data Streaming Pipelines:** Real-time Kafka/Kinesis stream ingestion is out of scope; Phase 5 operates on static/versioned dataset bundles.

---

## 3. Existing Architecture Integration

Phase 5 integrates seamlessly with the existing repository structure without modifying the Phase 4 cryptographic foundation:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           API Gateway (api/v1/datasets)                         │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
┌────────────────────────────────────────▼────────────────────────────────────────┐
│                        Services Layer (DatasetService)                          │
└──────────────────┬──────────────────────────────────────────────┬───────────────┘
                   │                                              │
┌──────────────────▼──────────────────┐        ┌──────────────────▼───────────────┐
│     Dataset Integrity Engine        │        │   Cryptographic Core (Phase 4)   │
│  ┌───────────────────────────────┐  │        │  - RFC 8785 Canonicalization    │
│  │ Ingestion & Normalization     │  │        │  - SHA-256 Hashing Engine        │
│  ├───────────────────────────────┤  │        │  - Ed25519 Key Signing           │
│  │ Fingerprinting (Image/Annot)  │  │        │  - Provenance Chain Engine       │
│  ├───────────────────────────────┤  │        │  - Tamper-Evident Audit Logging  │
│  │ Detection Analyzers (5x)      │  │        └──────────────────▲───────────────┘
│  ├───────────────────────────────┤  │                           │
│  │ Contributor Aggregator        │  │                           │
│  └───────────────┬───────────────┘  │                           │
└──────────────────┼──────────────────┘                           │
                   │ emits Evidence & Findings                    │
┌──────────────────▼──────────────────────────────────────────────┴───────────────┐
│              Database & Persistence Layer (models.py / SQLite WAL)              │
│  datasets | dataset_versions | samples | sample_contributors | findings | ev.   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Existing Entity Utilization
- **`DatasetModel` (`datasets` table):** Top-level dataset container bound to a `ProjectModel`.
- **`DatasetVersionModel` (`dataset_versions` table):** Tracks immutable version instances, sample counts, and composite `dataset_hash`.
- **`SampleModel` (`samples` table):** Stores individual image sample metadata, `file_hash_sha256`, `perceptual_hash`, image dimensions (`width`, `height`, `channels`), parsed `label_json`, `annotation_json`, and batch/provenance metadata.
- **`ContributorModel` & `SampleContributorModel` (`contributors`, `sample_contributors` tables):** ADR-029 normalized contributor attribution linking image samples to annotator/source IDs.
- **`FindingModel` & `EvidenceModel` (`findings`, `evidence` tables):** Stores detection results, confidence metrics, and structured evidence payloads under ADR-028 rules.
- **`AuditEventModel` & `ProvenanceRecordModel`:** Records dataset ingestion, hashing, and analysis events into the immutable cryptographic audit and provenance ledgers.

---

## 4. Dataset Ingestion Architecture

Dataset ingestion is deterministic, sandboxed, and resilient against directory traversal, malformed structures, and zip-bombs.

```
                  ┌──────────────────────────────┐
                  │    Raw Dataset Path / Zip    │
                  └──────────────┬───────────────┘
                                 │
                 ┌───────────────▼───────────────┐
                 │  Format Sniffer & Validator   │
                 └──────┬───────────────┬────────┘
                        │               │
            [Matches COCO]             [Matches YOLO]
            ┌───────────▼────────┐     ┌▼───────────────────┐
            │   COCO Ingester    │     │   YOLO Ingester    │
            └───────────┬────────┘     └┬───────────────────┘
                        │               │
                        └───────┬───────┘
                                │
                 ┌──────────────▼────────────────┐
                 │  Deterministic Normalization  │
                 │   - Sort lexicographically   │
                 │   - Canonicalize coordinate  │
                 │   - Strict Schema Validation  │
                 └──────────────┬────────────────┘
                                │
                 ┌──────────────▼────────────────┐
                 │    Canonical Manifest Stream  │
                 └───────────────────────────────┘
```

### 4.1 Format Recognition & Validation Flow
1. **Sniffing Stage:**
   - **COCO:** Presence of valid JSON file conforming to COCO structure (`images`, `annotations`, `categories` top-level keys).
   - **YOLO:** Presence of YAML definition (`dataset.yaml` or `data.yaml`) specifying `names` / `nc` and directory mapping, or standard paired `images/` and `labels/` sibling directories with `.txt` label files.
   - **ImageFolder:** Root directory containing subdirectories named by class labels, populated exclusively by valid image files.
2. **Path Traversal & Security Sandbox:**
   - All relative file paths inside manifests (`file_name`, `path`) are resolved strictly relative to the dataset root.
   - Symlinks pointing outside the dataset sandbox or circular references trigger immediate validation rejection (`DATASET_PATH_TRAVERSAL_DETECTED`).
3. **Format-Specific Ingestion Rules:**
   - **COCO:** Handles 1-indexed and 0-indexed category mappings, polygon segmentation lists, RLE segmentation, and bounding boxes formatted as `[x_min, y_min, width, height]`.
   - **YOLO:** Normalizes normalized center coordinates `[class_id, x_center, y_center, width, height]` (all in $[0, 1]$) into absolute canonical bounding boxes.
   - **ImageFolder:** Synthesizes single-label classification annotations with implicit category bounds.

---

## 5. Dataset Normalization Model

To ensure analyzer code is format-agnostic, the ingestion layer maps all input variations into a standardized internal representation:

```python
# Conceptual Schema (Pydantic / Dataclass)
class CanonicalBBox:
    x_min: float  # Absolute pixel coordinate (float64)
    y_min: float
    width: float
    height: float
    confidence: Optional[float] = 1.0

class CanonicalAnnotation:
    annotation_id: str
    category_id: int
    category_name: str
    bbox: Optional[CanonicalBBox] = None
    segmentation: Optional[List[List[float]]] = None
    area: Optional[float] = None
    is_crowd: bool = False
    attributes: Dict[str, Any]

class CanonicalSample:
    sample_id: str  # Deterministic UUID derived from project + relative_path
    relative_path: str  # Forward-slash normalized relative path
    file_size_bytes: int
    file_hash_sha256: str
    width: int
    height: int
    channels: int
    color_space: str  # "RGB", "RGBA", "L", "CMYK"
    annotations: List[CanonicalAnnotation]
    contributors: List[str]  # Contributor IDs
    metadata: Dict[str, Any]
```

### 5.1 Normalization Invariants
- **Path Separation:** All paths strictly use forward slashes (`/`), stripped of leading/trailing slashes.
- **Lexicographical Ordering:** Samples are processed and indexed in strict lexicographical order of `relative_path`.
- **Coordinate Precision:** Floating point coordinates are validated to be non-negative, finite, and clamped within image boundaries $[0, \text{dim}]$.
- **Annotation Sorting:** Annotations within a sample are sorted deterministically by `(category_id, x_min, y_min, width, height, annotation_id)`.

---

## 6. Dataset Fingerprinting

AIVARA establishes a dual cryptographic & structural identity for every dataset version.

```
Dataset Manifest
  ├── Sample 1 ──> SHA-256(Canonical Sample 1 JSON) ──┐
  ├── Sample 2 ──> SHA-256(Canonical Sample 2 JSON) ──┼──> Merkle Tree ──> Root SHA-256 Digest
  └── Sample N ──> SHA-256(Canonical Sample N JSON) ──┘
```

### 6.1 Composite Dataset Fingerprints
1. **Merkle Manifest Digest (`dataset_merkle_root`):**
   - Leaf nodes: Canonical RFC 8785 JCS serialization of each `CanonicalSample` record $\rightarrow \text{SHA-256}$.
   - Leaves are ordered strictly by `relative_path`.
   - Binary Merkle Tree computed using pairwise hashing: $\text{SHA-256}(\text{Leaf}_L \parallel \text{Leaf}_R)$.
   - Guarantees $O(\log N)$ proof of inclusion/exclusion for any individual image or annotation.
2. **Dataset Manifest Hash (`dataset_hash`):**
   - High-level metadata payload: `{"project_id": ..., "format": ..., "sample_count": N, "merkle_root": ..., "category_map": [...]}` canonicalized via RFC 8785 and hashed with SHA-256.
3. **Statistical Profile Vector:**
   - Vector encoding: Class distribution histograms, image dimension ratios, brightness/contrast moments, mean annotations per image.

---

## 7. Image Fingerprinting

Image fingerprinting combines exact cryptographic content integrity with perceptual robustness against re-encoding and compression.

### 7.1 Image-Level Fingerprint Pipeline

| Layer | Algorithm | Output Format | Invariant & Resilience |
|:---|:---|:---|:---|
| **Cryptographic Raw Digest** | SHA-256 over exact file bytes on disk | 64-char lowercase hex | 100% bit-exact integrity. Detects single-bit file tampering. |
| **Pixel Buffer Digest** | SHA-256 over decoded raw uncompressed RGB byte array | 64-char lowercase hex | Invariant to EXIF header mutations, lossless container re-saves, and metadata stripping. |
| **Perceptual Hash (pHash)** | Discrete Cosine Transform (DCT) based frequency analysis (32x32 $\rightarrow$ 8x8 low frequency DCT) | 64-bit hex (16-char hex string) | Invariant to JPEG compression, minor color adjustments, and scaling. |
| **Difference Hash (dHash)** | Grayscale 9x8 gradient comparative hash | 64-bit hex (16-char hex string) | Fast gradient tracker for near-duplicate screening. |
| **Visual Feature Embedding** | Deep Feature Vector (DINOv2 / CLIP / MobileNet-v3, offline-cached) | 512-d or 768-d float32 L2-normalized vector | High-level semantic representation for OOD and deep visual anomaly detection. |

---

## 8. Annotation Fingerprinting

Annotations must have deterministic cryptographic identities to detect subtle bounding box shifts, category re-labeling, and coordinate drift.

### 8.1 Single Annotation Digest
Each annotation is serialized to canonical JSON (RFC 8785):
$$\text{AnnotationHash} = \text{SHA-256}\left(\text{JCS}\left(\left\{\text{"cat"}: c, \text{"bbox"}: [x, y, w, h], \text{"seg"}: s\right\}\right)\right)$$

### 8.2 Image Annotation Set Digest
The composite annotation hash for a sample is computed by sorting all individual annotation hashes in lexicographical order:
$$\text{SampleAnnotationHash} = \text{SHA-256}\left(\text{AnnotationHash}_1 \parallel \text{AnnotationHash}_2 \parallel \dots \parallel \text{AnnotationHash}_K\right)$$

If an image has zero annotations (background/negative sample), $\text{SampleAnnotationHash} = \text{SHA-256}(\text{""}) = \text{e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}$.

---

## 9. Label Anomaly Detection Architecture

The Label Anomaly Detector identifies mislabeled samples, ambiguous ground truth, class overlap, and noisy annotations.

```
                          ┌──────────────────────────────┐
                          │   Dataset Feature Vectors    │
                          │   & Ground Truth Labels      │
                          └──────────────┬───────────────┘
                                         │
                 ┌───────────────────────▼───────────────────────┐
                 │       Cross-Validated Out-of-Fold             │
                 │      Class Probability Estimation             │
                 └───────────────────────┬───────────────────────┘
                                         │
                 ┌───────────────────────▼───────────────────────┐
                 │      Confident Learning Joint Distribution    │
                 │          $Q_{\tilde{y}, y^*}$ Estimation      │
                 └───────────────────────┬───────────────────────┘
                                         │
                         ┌───────────────┴───────────────┐
                         │                               │
        [Rank Self-Confidence $P(\tilde{y}|x)$]   [Normalized Margin]
                         │                               │
                         └───────────────┬───────────────┘
                                         │
                 ┌───────────────────────▼───────────────────────┐
                 │      Filter Label Noise Candidates            │
                 │    Emit Findings with Confidence Score        │
                 └───────────────────────────────────────────────┘
```

### 9.1 Algorithmic Strategy
1. **Out-of-Fold Predicted Probabilities:** Compute cross-validated predicted class probabilities $\hat{P}(y = k \mid x)$ using a fast linear probe / lightweight k-NN classifier on top of cached offline visual embeddings.
2. **Confident Learning Matrix Formulation:**
   - Compute class-specific self-confidence thresholds: $t_j = \frac{1}{|X_{\tilde{y}=j}|} \sum_{x \in X_{\tilde{y}=j}} \hat{P}(y = j \mid x)$.
   - Construct unnormalized joint distribution matrix $C_{\tilde{y}, y^*}$ where an example with given label $\tilde{y}$ is marked as belonging to latent true label $y^* = j$ if $\hat{P}(y = j \mid x) \ge t_j$.
3. **Anomaly Ranking Metric:**
   $$\text{LabelQualityScore}(x, \tilde{y}) = \hat{P}(y = \tilde{y} \mid x)$$
   Low scores indicate high likelihood of labeling error or feature ambiguity.

---

## 10. Label Flipping Detection Architecture

Adversarial label-flipping attacks involve deliberately corrupting labels of specific training instances from a source class $S$ to a target class $T$ to degrade model accuracy or induce targeted backdoor vulnerabilities.

### 10.1 Detection Methodology
1. **Asymmetric Transition Matrix Analysis:**
   - Construct empirical class error transition matrix $T_{i, j} = \text{Count}(\text{Given}=i \to \text{Predicted}=j)$.
   - Measure asymmetry score: $A_{i, j} = |T_{i, j} - T_{j, i}| / (T_{i, j} + T_{j, i} + \epsilon)$.
   - Naturally occurring noise tends to be symmetric or semantic (e.g., Cat $\leftrightarrow$ Dog), whereas targeted label-flipping attacks exhibit high directional asymmetry (e.g., Stop Sign $\to$ Speed Limit).
2. **Cluster Impurity & Spectral Outliers:**
   - In feature embedding space, identify points of class $T$ situated deeply inside the high-density convex hull of class $S$.
   - Calculate local reachability density and distance to source class centroid.
3. **Bimodal Loss Distribution:**
   - Check whether subset of suspect annotations exhibits an isolated high-confidence clustering pattern uncharacteristic of random annotator fatigue.

---

## 11. Near-Duplicate Detection Architecture

Near-duplicate images can indicate data leakage between splits, dataset contamination, copy-paste tampering, or uncurated crawling artifacts.

```
                           ┌──────────────────────────────┐
                           │      N Image Samples         │
                           └──────────────┬───────────────┘
                                          │
                 ┌────────────────────────▼────────────────────────┐
                 │    Compute 64-bit Perceptual Hashes (pHash)     │
                 └────────────────────────┬────────────────────────┘
                                          │
                 ┌────────────────────────▼────────────────────────┐
                 │    Index Hashes into Multi-Index Hash / BK-Tree │
                 │        (Sub-quadratic $O(N \log N)$ Index)      │
                 └────────────────────────┬────────────────────────┘
                                          │
                 ┌────────────────────────▼────────────────────────┐
                 │   Query Candidates with Hamming Radius $r \le 10$│
                 └────────────────────────┬────────────────────────┘
                                          │
                 ┌────────────────────────▼────────────────────────┐
                 │     Exact Pixel / Embedding Verification        │
                 │   Classify: EXACT_CLONE, RESCALED, CROP_VARIANT │
                 └─────────────────────────────────────────────────┘
```

### 11.1 Sub-Quadratic Scalability ($O(N \log N)$)
- **Direct $O(N^2)$ Pairwise Comparisons are STRICTLY PROHIBITED** for datasets exceeding 1,000 images.
- **Index Structure:**
  - 64-bit perceptual hashes are split into 4 16-bit chunks for Multi-Index Hashing (MIH) lookup tables, or indexed into a **BK-Tree (Burkhard-Keller Tree)** parameterized by Hamming distance metric.
  - Candidate retrieval bounds search radius to $r \le 10$ bits difference out of 64 bits.
- **Duplicate Taxonomy:**
  - **EXACT_CLONE:** SHA-256 bit-identical match (Hamming distance = 0, byte match).
  - **PERCEPTUAL_MATCH:** pHash Hamming distance $\le 3$, SSIM $\ge 0.98$ (re-compressed, re-encoded).
  - **CROPPED_TRANSFORMED:** Hamming distance $4 \le d \le 8$, deep feature cosine similarity $\ge 0.95$.

---

## 12. Out-of-Distribution (OOD) Detection Architecture

OOD detection identifies samples that do not belong to the target domain, corrupted images (extreme blur, sensor noise, zero-byte/blank frames), and anomalous outliers.

### 12.1 Multi-Resolution OOD Pipeline
1. **Low-Level Image Quality Scoring:**
   - **Blur Index:** Laplacian variance ($\sigma^2_{\Delta}$).
   - **Entropy & Dynamic Range:** Shannon entropy of pixel intensity histogram.
   - **Aspect Ratio & Dimension Extremes:** Statistical z-score of dimensions against dataset distribution.
2. **Semantic Embedding Space OOD:**
   - Fit a Minimum Covariance Determinant (MCD) robust Gaussian or compute **k-Nearest Neighbor (k-NN) Distance** in embedding space:
     $$D_k(x) = \|x - z^{(k)}\|_2$$
     where $z^{(k)}$ is the $k$-th nearest neighbor in the in-distribution reference set.
   - Calculate Isolation Forest anomaly score across the visual representation vector.

---

## 13. Contributor Aggregation

AIVARA maps dataset integrity findings back to annotators, data sources, and submission batches using the normalized schema from ADR-029.

```
       ┌───────────────────────────┐
       │   Dataset Findings Pool   │
       └─────────────┬─────────────┘
                     │
       ┌─────────────▼─────────────┐
       │ Join via sample_id on     │
       │ sample_contributors table │
       └─────────────┬─────────────┘
                     │
       ┌─────────────▼─────────────────────────────┐
       │ Contributor Integrity Aggregation Engine   │
       │   - Contributor Error Rate ($E_c$)         │
       │   - Contributor Label Flipping Rate       │
       │   - Duplicate Generation Ratio            │
       │   - Historical Reputation Weighting       │
       └─────────────┬─────────────────────────────┘
                     │
       ┌─────────────▼─────────────┐
       │ Contributor Profile Score │
       │   (Emitted to Evidence)   │
       └───────────────────────────┘
```

### 13.1 Contributor Risk Metrics
- **Error Concentration Ratio:**
  $$\text{ECR}(c) = \frac{\text{Anomalies from Contributor } c / \text{Total Samples from Contributor } c}{\text{Total Dataset Anomalies} / \text{Total Dataset Samples}}$$
  $\text{ECR} > 3.0$ highlights an annotator contributing disproportionate errors relative to dataset baseline.
- **Systematic Bias Indicator:** Measures if an annotator's errors are heavily concentrated on specific class-pair flips.

---

## 14. Evidence Model

In accordance with ADR-028, all findings generated by the Dataset Integrity Engine MUST be substantiated by structured, verifiable `Evidence` records.

### 14.1 Evidence Envelope Structure
```json
{
  "evidence_layer": "detection",
  "evidence_type": "dataset_label_anomaly",
  "title": "High-Confidence Label Inconsistency Detected on Sample 00482.jpg",
  "description": "Model predicted class 'pedestrian' with 94.2% confidence; given label is 'traffic_light'.",
  "data_json": {
    "sample_id": "4a18b762-81f3-4d69-9528-6617a2a07c91",
    "relative_path": "train/00482.jpg",
    "given_label": "traffic_light",
    "predicted_label": "pedestrian",
    "label_quality_score": 0.058,
    "feature_distance_to_centroid": 3.42,
    "contributor_id": "annotator_ext_104"
  },
  "artifact_path": "data/datasets/proj_1/samples/00482.jpg",
  "artifact_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "confidence": 0.942,
  "evidence_hash": "9f83c605... (SHA-256 of canonical data_json)"
}
```

---

## 15. Confidence Model

Confidence scores in Phase 5 represent mathematical certainty and statistical significance of the detection algorithm.

### 15.1 Confidence Calibration Matrix

| Engine / Detection Type | Method | Confidence Derivation Formula | Range |
|:---|:---|:---|:---:|
| **Cryptographic / Bit Integrity** | SHA-256 Content Match | Deterministic Proof ($1.0$ if mismatch, $0.0$ if match) | $\{0.0, 1.0\}$ |
| **Exact Duplicate** | Exact SHA-256 Collision | $1.0$ (Bit-exact match) | $1.0$ |
| **Near-Duplicate (pHash)** | Normalized Hamming Distance $d$ | $\text{Confidence} = 1.0 - \frac{d}{\text{Threshold}}$ for $d \le \text{Threshold}$ | $[0.70, 1.0]$ |
| **Label Anomaly** | Softmax Margin & Density | $\text{Confidence} = \hat{P}(y_{\text{pred}} \mid x) - \hat{P}(y_{\text{given}} \mid x)$ | $[0.0, 1.0]$ |
| **OOD / Outlier** | k-NN / Isolation Forest Score | Normalized percentile rank against empirical distribution | $[0.0, 1.0]$ |

---

## 16. Failure Semantics & Semantic Boundaries

### 16.1 Fundamental Semantic Boundary: Anomaly $\neq$ Maliciousness
An observation of an anomaly MUST NOT automatically trigger an assertion of malicious attack or adversarial intent.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      AIVARA OBSERVATION TAXONOMY                                │
│                                                                                 │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────┐   │
│   │    NORMAL    │     │  ANOMALOUS   │     │  SUSPICIOUS  │     │UNVERIFI- │   │
│   │              │     │              │     │              │     │  ABLE    │   │
│   │ Expected,    │     │ Statistical  │     │ Coordinated, │     │Malformed,│   │
│   │ standard     │     │ variance,    │     │ asymmetric,  │     │unreadable│   │
│   │ data pattern │     │ noisy label  │     │ high-density │     │corrupted │   │
│   └──────────────┘     └──────────────┘     └──────────────┘     └──────────┘   │
│                                │                                                │
│                                ▼                                                │
│         [Phase 8 Downstream Evidence & Risk Correlation Layer]                  │
│                                │                                                │
│                                ▼                                                │
│                      ┌──────────────────┐                                       │
│                      │    MALICIOUS     │                                       │
│                      │ (Concluded ONLY  │                                       │
│                      │ with sufficient  │                                       │
│                      │ evidence trail)  │                                       │
│                      └──────────────────┘                                       │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 16.2 Failure Classification Taxonomy

| Failure Classification | Meaning | System Reaction & Status |
|:---|:---|:---|
| `INVALID_DATASET_STRUCTURE` | Root directory is missing required manifest, structure is unrecognized | Scan fails immediately; structured error returned. |
| `UNSUPPORTED_DATASET_FORMAT` | Format recognized but unsupported version/variant | Scan rejected with explanatory capability message. |
| `MALFORMED_ANNOTATION` | JSON syntax error, coordinates out of range, negative box size | Sample marked `UNVERIFIABLE`; scan continues for remainder. |
| `UNREADABLE_IMAGE` | Corrupted image header, truncated file, invalid codec | Sample marked `CORRUPTED_IMAGE`; logged; scan continues. |
| `DETECTOR_UNAVAILABLE` | Feature extractor / embedding model disabled in offline config | Detector skipped gracefully; capability limitation noted. |
| `DETECTOR_EXECUTION_FAILURE` | Numerical exception / OOM during specific analyzer pass | Finding emitted with status `DETECTOR_ERROR`; partial results saved. |
| `SUSPICIOUS_FINDING` | Statistical / visual anomaly identified above threshold | Finding emitted with `disposition: review` and confidence score. |
| `CRYPTOGRAPHIC_INTEGRITY_VIOLATION` | Manifest hash or sample digest mismatch against prior baseline | Finding emitted with `disposition: quarantine`, `confidence: 1.0`. |

---

## 17. Offline & Air-Gapped Operation

AIVARA operates in strict air-gapped secure environments.

### 17.1 Offline Invariants
1. **Zero Runtime Network I/O:** Socket connections to external IPs/domains are blocked by architecture. No calls to Hugging Face Hub, PyPI, AWS S3, or telemetry backends.
2. **Local Weight & Asset Bundling:** All reference model weights (e.g. DINOv2 / MobileNet backbone) must be pre-staged in `data/model_cache/` or packaged within container images.
3. **Pure-Python & Pinned Local Binaries:** Algorithms rely strictly on standard library, NumPy, SciPy, Pillow, and pinned local wheels.

---

## 18. Scalability Strategy

The engine is engineered to handle datasets ranging from 100 samples up to 100,000+ samples without quadratic bottlenecks.

### 18.1 Computational Complexity Bounds

| Operation | Baseline / Brute Force | AIVARA Phase 5 Scalable Design | Time Complexity |
|:---|:---:|:---|:---:|
| **Sample Ingestion** | Iterative file open | Streaming generator + batch DB bulk inserts | $O(N)$ |
| **Merkle Tree Computation** | Recursive string concat | Binary leaves streaming hash reduction | $O(N)$ |
| **Duplicate Image Search** | Pairwise distance $N(N-1)/2$ | Multi-Index Hash / BK-Tree over 64-bit pHash | $O(N \log N)$ |
| **Feature Extraction** | Single image inference | Batched PyTorch/ONNX inference with memory pooling | $O(N)$ |
| **Label Anomaly Detection** | Full dataset matrix inversion | Out-of-fold linear probe with mini-batching | $O(N)$ |

---

## 19. Graceful Degradation & Capability Matrix

If high-resource components (e.g., GPU, embedding models) are absent in a minimal air-gapped deployment, the system degrades gracefully rather than aborting.

```
                      ┌────────────────────────────┐
                      │    System Startup Check    │
                      └─────────────┬──────────────┘
                                    │
               ┌────────────────────┴────────────────────┐
               │                                         │
        [Embeddings Present]                      [Embeddings Missing]
               │                                         │
        ┌──────▼───────────────────┐              ┌──────▼───────────────────┐
        │     Full Mode (Tier 1)   │              │   Lightweight Mode       │
        │ - pHash + Feature Cosine │              │        (Tier 2)          │
        │ - Confident Learning     │              │ - pHash Near-Duplicates  │
        │ - Deep OOD k-NN          │              │ - Class Frequency Shifts │
        │ - Full Contributor Score │              │ - Image Quality Moments  │
        └──────────────────────────┘              │ - Metadata Verification  │
                                                  │ * Explicit Limitation    │
                                                  │   reported in findings   │
                                                  └──────────────────────────┘
```

---

## 20. Reproducibility Strategy

Given identical dataset files and configuration, all fingerprints and algorithmic findings MUST be 100% deterministic and bit-for-bit reproducible.

### 20.1 Determinism Enforcement
1. **Random Seed Pinning:** All stochastic operations (cross-validation splits, k-NN clustering) initialize with fixed seed `42` (or caller-supplied config seed).
2. **Deterministic Traversal:** Directory traversal and manifest parsing sort paths strictly via `sort(key=lambda p: p.as_posix())`.
3. **Canonical JSON Output:** All structured dictionaries are serialized using RFC 8785 JSON Canonicalization Scheme (JCS).
4. **Floating-Point Stability:** Matrix thresholds compute using standard 64-bit IEEE 754 precision with strict epsilon stabilization ($\epsilon = 10^{-7}$).

---

## 21. Configuration & Threshold Strategy

No detection threshold shall be hard-coded in analyzer routines. All parameters are exposed via typed configuration schemas.

### 21.1 Configuration Schema (`DatasetEngineConfig`)
```toml
# config/dataset_engine.toml
[dataset_engine]
enabled = true
max_workers = 4
batch_size = 64
random_seed = 42

[dataset_engine.near_duplicates]
enabled = true
phash_hamming_threshold = 6
ssim_threshold = 0.95
index_type = "bk_tree"

[dataset_engine.label_anomalies]
enabled = true
confidence_margin_threshold = 0.40
out_of_fold_cv_folds = 5

[dataset_engine.label_flipping]
enabled = true
asymmetry_threshold = 0.65
min_cluster_size = 5

[dataset_engine.ood]
enabled = true
laplacian_blur_threshold = 100.0
knn_distance_percentile = 0.95
```

---

## 22. Persistence Strategy

Phase 5 reuses existing Phase 3 relational schema entities without requiring database migrations during this design sub-phase:

1. **`DatasetModel` & `DatasetVersionModel`:** Persists dataset metadata, format, sample counts, and top-level `dataset_hash`.
2. **`SampleModel`:** Persists image dimensions, file SHA-256, perceptual hash, parsed label JSON, and annotation JSON.
3. **`FindingModel`:** Persists each identified anomaly, severity, confidence, affected asset, and initial disposition (`accept`, `review`, `quarantine`).
4. **`EvidenceModel`:** Persists detailed evidence payloads (`data_json`), artifact paths, and SHA-256 evidence digests.
5. **`AuditEventModel`:** Automatically records `DATASET_IMPORTED`, `DATASET_VERSION_CREATED`, and `DATASET_AUDIT_COMPLETED` events into the hash-linked audit chain.

---

## 23. Integration with Phase 4 Cryptographic Provenance

Dataset analysis events and resulting digests are cryptographically anchored to Phase 4 provenance records:

1. **Ingestion Sealed Record:**
   - `record_type = "DATASET_INGESTION"`
   - `input_hash = dataset_merkle_root`
   - `output_hash = dataset_hash`
   - Signed with active project Ed25519 key $\rightarrow$ Appended to project provenance chain.
2. **Audit Verification Anchor:**
   - Scan completion records `record_type = "DATASET_INTEGRITY_SCAN"` containing summary findings digest, total anomalies count, and config hash.

---

## 24. API Integration Plan

Phase 5 will expose clean, thin REST endpoints under `/api/v1/datasets/`:

```
POST /api/v1/datasets/import                   # Ingest dataset from directory or archive
GET  /api/v1/datasets/{id}/manifest            # Retrieve canonical dataset manifest & Merkle root
POST /api/v1/datasets/{id}/scan                # Trigger asynchronous dataset integrity scan
GET  /api/v1/datasets/{id}/scan/{scan_id}      # Get scan status, progress, and summary
GET  /api/v1/datasets/{id}/findings            # Paginated query of dataset findings & evidence
GET  /api/v1/datasets/{id}/duplicates          # Query near-duplicate clusters
GET  /api/v1/datasets/{id}/contributors/risk   # Query contributor aggregation metrics
```

---

## 25. Testing Strategy

The test suite for Phase 5 will follow a comprehensive, multi-layer verification structure:

### 25.1 Test Categories & Suites

| Suite ID | Category | Focus Areas & Test Scenarios |
|:---|:---|:---|
| **TEST-DIE-01** | Unit & Parser Tests | COCO, YOLO, and ImageFolder valid and boundary format parsers. |
| **TEST-DIE-02** | Malformed Dataset Tests | Truncated files, invalid JSON, negative coordinates, out-of-bounds bounding boxes, missing images. |
| **TEST-DIE-03** | Adversarial Ingestion Tests | Directory traversal (`../../etc/passwd`), zip bombs, circular symlinks. |
| **TEST-DIE-04** | Fingerprinting & Merkle Tests | Merkle root determinism, single-bit perturbation detection, image pHash stability under re-encoding. |
| **TEST-DIE-05** | Label Anomaly Tests | Verification against synthetic datasets with known injected label noise ($10\%, 20\%$). |
| **TEST-DIE-06** | Label Flipping Tests | Detection of directed class-flip attacks ($A \to B$) across various attack fractions. |
| **TEST-DIE-07** | Near-Duplicate Tests | Exact clones, JPEG recompression ($Q=50$), scaled down ($50\%$), cropped variants ($10\%$). |
| **TEST-DIE-08** | OOD & Quality Tests | Solid color images, extreme Gaussian blur, white noise, mismatched resolution. |
| **TEST-DIE-09** | Contributor Aggregation Tests | Multi-contributor error attribution and concentration ratio validation. |
| **TEST-DIE-10** | Graceful Degradation Tests | Execution validation when visual embedding models are absent. |
| **TEST-DIE-11** | Scalability & Sub-Quadratic Tests | Execution time verification on $N=1,000$ and $N=10,000$ showing sub-quadratic scaling. |
| **TEST-DIE-12** | Deterministic Reproducibility Tests | Multi-run consistency of findings and hash digests across repeated executions. |

---

## 26. Explicit Unsupported Cases & Limitations

To maintain transparent assurance, AIVARA explicitly declares unsupported formats and detection limitations:

1. **Unsupported Annotation Formats (Phase 5):**
   - Pascal VOC XML (Planned for future extension).
   - LiDAR 3D Bounding Boxes.
   - Video tracking sequence manifests.
2. **Known Detection Limitations:**
   - **Clean-Label Backdoors:** Imperceptible pixel-space triggers without label modification or feature-space clustering cannot be detected by Dataset Integrity Engine alone (requires Phase 7 Backdoor/Trigger Engine).
   - **Low-Rate Uniform Label Noise:** Random label noise $< 1\%$ across hundreds of balanced classes may fall below statistical significance thresholds.
   - **Heavy Geometric Crops:** Crops retaining $< 20\%$ of original image area cannot be detected by standard perceptual hashing.

---

## 27. Security Considerations

1. **Local Denial of Service (DoS):**
   - Decompression bombs are mitigated by strictly enforcing max uncompressed byte thresholds (`MAX_DECOMPRESSED_DATASET_BYTES = 50GB`).
   - Image pixel decompression bombs (e.g. 100,000 x 100,000 1-bit images) are rejected via `Image.MAX_IMAGE_PIXELS` safety bounds.
2. **Memory Safety & Process Isolation:**
   - Large image decoding operations are streamed and bounded in memory.
3. **No Code Execution:**
   - Config files, YAML files, and JSON annotations are parsed using safe loaders (`yaml.safe_load`, `json.loads`) with zero dynamic code execution or `pickle` deserialization.

---

## 28. Phase 5 Sub-Phase Roadmap

The implementation of Phase 5 will proceed sequentially across modular, independently testable sub-phases:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           PHASE 5 EXECUTION ROADMAP                             │
├───────────────────┬─────────────────────────────────────────────────────────────┤
│ Sub-Phase         │ Title & Scope                                               │
├───────────────────┼─────────────────────────────────────────────────────────────┤
│ **Phase 5.1**     │ Architecture Review & Design Freeze (Current - Completed)   │
│ **Phase 5.2**     │ Ingestion & Normalization Engine (COCO, YOLO, ImageFolder)  │
│ **Phase 5.3**     │ Multi-Tier Fingerprinting & Merkle Tree Integrity Engine    │
│ **Phase 5.4**     │ Near-Duplicate Detection Engine (MIH / BK-Tree Scalable)    │
│ **Phase 5.5**     │ Label Anomaly & Confident Learning Detection Engine         │
│ **Phase 5.6**     │ Targeted Label-Flipping Detection Engine                    │
│ **Phase 5.7**     │ Out-of-Distribution (OOD) & Image Quality Engine            │
│ **Phase 5.8**     │ Contributor Risk Aggregation Engine                         │
│ **Phase 5.9**     │ Evidence Generation & Provenance Ledger Integration         │
│ **Phase 5.10**    │ REST API Adapters & Engine Orchestration Service           │
│ **Phase 5.11**    │ Comprehensive Phase 5 Test Suite & Performance Verification │
└───────────────────┴─────────────────────────────────────────────────────────────┘
```
