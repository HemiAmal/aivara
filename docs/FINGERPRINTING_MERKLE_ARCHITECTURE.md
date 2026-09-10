# AIVARA — Multi-Tier Fingerprinting & Merkle Tree Architecture Specification
## Phase 5.3.1: Architecture Review & Design Freeze

**Version:** 1.0.0-frozen  
**Status:** DESIGN FROZEN (Implementation Target: Phase 5.3)  
**Security Classification:** Cryptographic Dataset Assurance Layer  
**Target Sub-System:** Phase 5.3 — Multi-Tier Fingerprinting & Merkle Tree Integrity Engine  

---

## 1. Scope

This specification establishes the deterministic cryptographic fingerprinting and Merkle tree integrity architecture for AIVARA (Phase 5.3). 

The primary objective is to define a layered cryptographic identity for:
1. **Raw image files on disk** (bit-exact filesystem integrity)
2. **Decoded RGB pixel buffers** (container-independent visual pixel integrity)
3. **Bounding-box and segmentation annotations** (semantic coordinate & label integrity)
4. **Canonical samples** (composite sample-level cryptographic identity)
5. **Complete datasets** (hierarchical binary Merkle tree root and canonical dataset manifest digest)

```
                            Canonical Dataset Manifest
                                      │
                ┌─────────────────────┴─────────────────────┐
                ▼                                           ▼
         Canonical Sample 0                          Canonical Sample N
         ├── raw_image_sha256                        ├── raw_image_sha256
         ├── decoded_rgb_sha256                      ├── decoded_rgb_sha256
         ├── annotation_set_hash                     ├── annotation_set_hash
         └── metadata / paths                        └── metadata / paths
                │                                           │
                ▼                                           ▼
          Sample Fingerprint 0                        Sample Fingerprint N
                │                                           │
                ▼                                           ▼
         [ Merkle Leaf 0 ]                           [ Merkle Leaf N ]
                └─────────────────────┬─────────────────────┘
                                      │
                           Deterministic Leaf Order
                             (RFC 6962 Structure)
                                      │
                                      ▼
                             Binary Merkle Tree
                                      │
                                      ▼
                             dataset_merkle_root
                                      │
                                      ▼
                                dataset_hash
```

---

## 2. Non-Goals

To preserve clean modularity and avoid premature complexity, the following are strictly out of scope for Phase 5.3:
1. **Perceptual Hashes (pHash / dHash):** Perceptual hashing and Hamming distance matching belong to Phase 5.4 (Near-Duplicate Detection Engine).
2. **Deep Visual Embeddings (DINOv2 / MobileNet / CLIP):** Embedding feature extractors belong to Phase 5.5 and Phase 5.7.
3. **Near-Duplicate Indexing (BK-Tree / MIH):** Multi-index spatial hashing structures belong to Phase 5.4.
4. **Statistical Analyzers & Confident Learning:** Label noise and out-of-fold estimators belong to Phase 5.5.
5. **Targeted Label-Flipping Analyzers:** Error transition matrices belong to Phase 5.6.
6. **Out-of-Distribution Scoring:** OOD algorithms belong to Phase 5.7.
7. **Contributor Risk Scoring:** Annotator risk aggregation belongs to Phase 5.8.
8. **REST API Routing & Frontend:** API endpoints belong to Phase 5.10.
9. **Database Schema Migrations:** Zero schema migrations in this phase.

---

## 3. Existing Architecture Integration

Phase 5.3 directly reuses and builds upon the frozen core components:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│              Phase 5.2 Canonical Ingestion Boundary (FROZEN)                    │
│   CanonicalSample │ CanonicalAnnotation │ CanonicalBBox │ CanonicalManifest     │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
┌────────────────────────────────────────▼────────────────────────────────────────┐
│         Phase 5.3 Multi-Tier Fingerprinting & Merkle Engine (NEW)               │
│  ┌───────────────────────────┐  ┌───────────────────────────┐  ┌─────────────┐  │
│  │ Level 0: Raw File Digest  │  │ Level 1: Pixel Digest     │  │ Level 2:    │  │
│  │ (SHA-256 Stream)          │  │ (Decoded RGB Buffer)      │  │ Annotations │  │
│  └─────────────┬─────────────┘  └─────────────┬─────────────┘  └──────┬──────┘  │
│                └──────────────────────┬───────┘                       │         │
│                                       ▼                               ▼         │
│                        Level 3: Canonical Sample Fingerprint                    │
│                                       │                                         │
│                        Level 4: RFC 6962 Binary Merkle Tree                     │
│                        ├── dataset_merkle_root                                  │
│                        └── dataset_hash                                         │
└───────────────────────────────────────┬─────────────────────────────────────────┘
                                        │
┌───────────────────────────────────────▼─────────────────────────────────────────┐
│              Phase 4 Cryptographic Core (FROZEN & REUSED)                       │
│  - RFC 8785 / JCS Canonical Serialization (crypto/canonical.py)                │
│  - SHA-256 Hashing Engine (crypto/hashing.py)                                   │
│  - Ed25519 Provenance Ledger & Audit Engine (crypto/chain.py, audit.py)         │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Reused Cryptographic Primitives:
- `aivara.crypto.canonical.canonicalize()`: Implements RFC 8785 JSON Canonicalization Scheme (JCS).
- `aivara.crypto.hashing.sha256_bytes()`: Constant-time deterministic SHA-256 digest computation.
- `aivara.crypto.hashing.constant_time_compare()`: Timing-attack resistant digest comparisons.

---

## 4. Multi-Tier Fingerprint Hierarchy

The fingerprint hierarchy establishes five distinct verification layers:

| Level | Identifier | Input Domain | Output Representation | Security Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **Level 0** | `raw_image_sha256` | Raw file byte stream on disk | 64-char lowercase hex | 100% bit-exact disk integrity |
| **Level 1** | `decoded_rgb_sha256` | Uncompressed sRGB 8-bit row-major pixel buffer | 64-char lowercase hex | Container & metadata invariant visual pixel integrity |
| **Level 2** | `annotation_set_hash` | JCS-canonicalized bounding boxes & categories | 64-char lowercase hex | Referential, geometric & semantic label integrity |
| **Level 3** | `sample_fingerprint` | Composite `CanonicalSample` schema | 64-char lowercase hex | Complete sample identity (image + pixels + labels + path) |
| **Level 4** | `dataset_merkle_root` | Ordered binary Merkle tree of leaf hashes | 64-char lowercase hex | $O(\log N)$ tamper-evident inclusion proof & whole-dataset proof |
| **Level 4+** | `dataset_hash` | JCS-canonicalized `CanonicalDatasetManifest` | 64-char lowercase hex | Global dataset manifest digest binding metadata to Merkle root |

---

## 5. Level 0: Raw File Fingerprint (`raw_image_sha256`)

### 5.1 Specification
- **Algorithm:** SHA-256 (FIPS 180-4) computed over the exact binary file content on disk.
- **Chunking / Streaming:** Streamed in 64 KiB ($65,536$ bytes) buffers to prevent loading large images into memory.
- **Format:** 64-character lowercase hexadecimal string (`[0-9a-f]{64}`).
- **Domain Tag:** `aivara-rawfile-v1:` (used when embedded in higher-level canonical structures).

### 5.2 Failure & Edge Case Semantics
- **Missing File:** Raises `MissingImageError`.
- **Unreadable File / Permission Denied:** Raises `InvalidImageError`.
- **Empty File (0 bytes):** Evaluates to standard empty SHA-256 digest `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (and will subsequently fail Level 1 image decoding).
- **Corrupt File:** Successfully computes raw SHA-256 (capturing disk state), but fails subsequent Level 1 decoding.

---

## 6. Level 1: Decoded Pixel Fingerprint (`decoded_rgb_sha256`)

### 6.1 Specification
The decoded pixel fingerprint guarantees that two files with identical decoded RGB pixel grids produce the exact same cryptographic hash, even if EXIF headers, metadata, compression artifacts, or file containers differ.

- **Color Space Standard:** sRGB, 8 bits per channel (24 bits per pixel).
- **Channel Order:** Interleaved RGB ($R, G, B, R, G, B, \dots$).
- **Spatial Order:** Row-major top-to-bottom, left-to-right.
- **Alpha Handling:**
  - If input has an Alpha channel (RGBA), it is composited over a solid white background `(255, 255, 255)` or stripped into pure RGB using standard alpha blending:
    $$\text{RGB}_{\text{out}} = \alpha \cdot \text{RGB} + (1 - \alpha) \cdot 255$$
- **Grayscale Handling:**
  - 1-channel Grayscale ($L$) is converted to 3-channel RGB by duplicating the luminance value across all three channels: $(L, L, L)$.
- **Bit Depth Normalization:**
  - 16-bit per channel images (e.g. 16-bit PNG/TIFF) are scaled to 8-bit via integer division $\lfloor v / 257 \rfloor$ or standard PIL 8-bit conversion.
- **Orientation Normalization:**
  - EXIF orientation tags are resolved prior to pixel extraction (image is transposed to canonical top-left orientation).

### 6.2 Pixel Digest Formula
To prevent cross-dimension collisions (e.g., an image of $2 \times 3$ having the same byte stream as $3 \times 2$), the decoded byte buffer is prefixed with a binary domain header:

$$\text{Header} = \text{UTF-8}\left(\text{"aivara-pixels-v1:"} \parallel W \parallel \text{":"} \parallel H \parallel \text{":"} \parallel C \parallel \text{":"}\right)$$
$$\text{decoded\_rgb\_sha256} = \text{SHA-256}\left(\text{Header} \parallel \text{RawRGBByteStream}\right)$$

### 6.3 Memory & Streaming Guarantees
- Pixel extraction is performed row-by-row or tile-by-tile via streaming decoders where possible to ensure maximum memory footprint per sample is bounded by $O(W \times H \times 3)$ bytes and garbage-collected immediately.

---

## 7. Level 2: Annotation Fingerprint (`annotation_set_hash`)

### 7.1 Single Annotation Digest
Each `CanonicalAnnotation` is serialized into a deterministic RFC 8785 JCS dictionary:

```json
{
  "annotation_id": "annot-001",
  "area": 12000.0,
  "attributes": {},
  "bbox": [10.0, 20.0, 100.0, 120.0],
  "category_id": 1,
  "category_name": "car",
  "is_crowd": false,
  "segmentation": null
}
```

#### Coordinate Precision & Quantization Rules:
- Floating-point coordinates in `bbox` (`[x_min, y_min, width, height]`) and `segmentation` are rounded to **4 decimal places** (`round(val, 4)`) before canonicalization to eliminate sub-micron IEEE-754 precision noise across operating systems.
- Canonical JSON serialization is performed via RFC 8785 JCS.
- Single annotation digest formula:
  $$\text{AnnotHash} = \text{SHA-256}\left(\text{UTF-8}(\text{"aivara-annot-v1:"}) \parallel \text{JCS}(\text{AnnotationDict})\right)$$

### 7.2 Composite Sample Annotation Set Hash
For a sample containing $K$ annotations:
1. Compute $\text{AnnotHash}_i$ for each annotation $i \in \{1, \dots, K\}$.
2. Sort the $K$ 32-byte digests in **lexicographical binary order** (ascending).
3. If $K = 0$ (negative/background sample with no annotations):
   $$\text{annotation\_set\_hash} = \text{SHA-256}\left(\text{UTF-8}(\text{"aivara-annotset-v1:empty"})\right)$$
4. If $K > 0$:
   $$\text{annotation\_set\_hash} = \text{SHA-256}\left(\text{UTF-8}(\text{"aivara-annotset-v1:"}) \parallel \text{AnnotHash}_{(1)} \parallel \dots \parallel \text{AnnotHash}_{(K)}\right)$$

---

## 8. Level 3: Canonical Sample Fingerprint (`sample_fingerprint`)

The sample fingerprint binds the image, its decoded pixels, its annotations, and its path into a unified, versioned cryptographic identity.

### 8.1 Sample Fingerprint Payload
Construct the canonical sample dictionary:

```json
{
  "schema_version": "1.0",
  "sample_id": "sample-001",
  "relative_path": "images/train/0001.jpg",
  "file_size_bytes": 204850,
  "width": 1920,
  "height": 1080,
  "channels": 3,
  "color_space": "RGB",
  "raw_image_sha256": "4a1b2c3d...",
  "decoded_rgb_sha256": "8e7f6a5b...",
  "annotation_set_hash": "c1d2e3f4...",
  "annotation_count": 3,
  "contributors": ["annotator-01", "annotator-02"],
  "metadata": {}
}
```

### 8.2 Invariants & Rules:
- `contributors` must be sorted lexicographically in ascending order.
- `relative_path` must be POSIX-normalized with forward slashes and no leading/trailing slashes.
- Canonical serialization is performed via RFC 8785 JCS.

### 8.3 Sample Fingerprint Formula
$$\text{sample\_fingerprint} = \text{SHA-256}\left(\text{UTF-8}(\text{"aivara-sample-v1:"}) \parallel \text{JCS}(\text{SampleDict})\right)$$

---

## 9. Domain Separation Architecture

To prevent cross-type collision attacks and second-preimage attacks (where an attacker crafts an internal node payload that collides with a leaf node or annotation), all hashing layers enforce strict 1-byte or string domain tags:

```
┌──────────────────────────┬──────────────────────┬────────────────────────────────────────────────────────┐
│ Target Object            │ Domain Prefix (Tag)  │ Serialization Format                                   │
├──────────────────────────┼──────────────────────┼────────────────────────────────────────────────────────┤
│ Raw File Stream          │ "aivara-rawfile-v1:" │ Raw bytes from disk                                    │
│ Decoded Pixel Buffer     │ "aivara-pixels-v1:"  │ "aivara-pixels-v1:W:H:C:" + raw RGB byte buffer        │
│ Single Annotation        │ "aivara-annot-v1:"   │ "aivara-annot-v1:" + RFC 8785 JCS(Annotation)          │
│ Sample Annotation Set    │ "aivara-annotset-v1:"│ "aivara-annotset-v1:" + sorted(AnnotHash_1..K)         │
│ Canonical Sample Record  │ "aivara-sample-v1:"  │ "aivara-sample-v1:" + RFC 8785 JCS(SampleDict)         │
│ Merkle Leaf Node         │ 0x00                 │ 0x00 || raw_32_byte_sample_fingerprint                 │
│ Merkle Internal Node     │ 0x01                 │ 0x01 || left_child_32_bytes || right_child_32_bytes    │
│ Empty Merkle Tree        │ "aivara-empty-tree"  │ "aivara-empty-tree-v1"                                 │
│ Canonical Dataset Hash   │ "aivara-dataset-v1:" │ "aivara-dataset-v1:" + RFC 8785 JCS(ManifestDict)      │
└──────────────────────────┴──────────────────────┴────────────────────────────────────────────────────────┘
```

**Security Property:** Because `0x00` and `0x01` prefixes differ at byte position 0, no internal node can ever collide with a leaf node (RFC 6962 compliance).

---

## 10. Level 4: Merkle Leaf Definition & Ordering

### 10.1 Merkle Leaf Construction
For sample $i$ with 64-char hex `sample_fingerprint` $F_i$:
1. Decode $F_i$ from hexadecimal into 32 raw bytes: $B_i = \text{bytes.fromhex}(F_i)$.
2. The Merkle leaf digest $L_i$ is computed as:
   $$L_i = \text{SHA-256}\left(\text{0x00} \parallel B_i\right)$$

### 10.2 Strict Deterministic Leaf Ordering
The Merkle tree is constructed over leaves sorted by **Canonical Dataset-Relative Path**:
1. All samples in the dataset are sorted strictly by `relative_path` in ascending byte order (UTF-8 binary collation).
2. **Duplicate Path Invariant:** If two samples have the exact same `relative_path`, ingestion MUST fail with `DuplicatePathError`. Under no circumstances are duplicate paths silently deduped or merged.
3. **Cross-Platform Path Invariant:** Windows backslashes (`\`) are normalized to POSIX forward slashes (`/`) prior to sorting.
4. **Unicode Normalization:** Paths are normalized to Unicode NFC before collation.

---

## 11. Merkle Tree Construction Algorithm (RFC 6962 Compliant)

### 11.1 Balanced Binary Splitting (Avoiding CVE-2012-2459)
In Bitcoin-style Merkle trees, odd leaves are duplicated at the boundary ($L_N \parallel L_N$). This creates a well-known vulnerability (CVE-2012-2459) where different leaf counts can produce identical Merkle roots.

**AIVARA adopts the RFC 6962 / Certificate Transparency tree construction algorithm:**
- For a list of $N$ leaves:
  1. If $N = 0$: $\text{root} = \text{SHA-256}(\text{"aivara-empty-tree-v1"})$.
  2. If $N = 1$: $\text{root} = L_0$.
  3. If $N > 1$:
     - Find $k = 2^{\lfloor \log_2(N - 1) \rfloor}$, which is the largest power of 2 strictly less than $N$.
     - Split the leaves into left sub-array $L[0 \dots k]$ and right sub-array $L[k \dots N]$.
     - Recursively compute:
       $$\text{LeftRoot} = \text{MerkleTree}(L[0 \dots k])$$
       $$\text{RightRoot} = \text{MerkleTree}(L[k \dots N])$$
     - Compute the parent node digest:
       $$\text{ParentNode} = \text{SHA-256}\left(\text{0x01} \parallel \text{LeftRoot}_{\text{raw}} \parallel \text{RightRoot}_{\text{raw}}\right)$$

```
Example: N = 5 leaves (k = 4)
                        Root
                       /    \
                     N_4     L_4
                   /     \
                 N_2     N_3
                /   \   /   \
               L_0 L_1 L_2 L_3
```

**Benefits of RFC 6962 Splitting:**
- **Zero Node Duplication:** Eliminates duplicate-node collision attacks.
- **Minimal Height:** Guarantees balanced tree height $\lceil \log_2 N \rceil$.
- **Deterministic Structure:** Strictly fixed topology for any integer $N \ge 0$.

---

## 12. Dataset Merkle Root (`dataset_merkle_root`)

- **Format:** 64-character lowercase hexadecimal string.
- **Empty Dataset Root:** $\text{SHA-256}(\text{"aivara-empty-tree-v1"}) = \text{a371...}$ (fixed deterministic constant).
- **Single Sample Dataset:** Equals the 64-character lowercase hex of $L_0$.
- **N-Sample Dataset:** Equals the 64-character lowercase hex of the final root node.

---

## 13. Canonical Dataset Digest (`dataset_hash`)

The `dataset_hash` represents the complete dataset container identity, binding the structural Merkle root to the dataset format, name, category hierarchy, and sample counts.

### 13.1 Manifest Payload Dictionary
```json
{
  "schema_version": "1.0",
  "fingerprint_version": "1.0",
  "format": "coco",
  "dataset_name": "vehicle-detection-val",
  "dataset_merkle_root": "e3b0c44298fc1c149afbf4c8...",
  "sample_count": 5000,
  "annotation_count": 14250,
  "categories": [
    {"category_id": 1, "category_name": "car", "supercategory": "vehicle"},
    {"category_id": 2, "category_name": "truck", "supercategory": "vehicle"}
  ],
  "metadata": {}
}
```

### 13.2 Dataset Hash Formula
$$\text{dataset\_hash} = \text{SHA-256}\left(\text{UTF-8}(\text{"aivara-dataset-v1:"}) \parallel \text{JCS}(\text{ManifestDict})\right)$$

**Difference between `dataset_merkle_root` and `dataset_hash`:**
- `dataset_merkle_root`: Cryptographic digest over the sample content trees (allows $O(\log N)$ inclusion proofs of individual samples).
- `dataset_hash`: Top-level cryptographic anchor binding high-level metadata, categories, and format to the Merkle root.

---

## 14. Merkle Inclusion Proof Design

Merkle inclusion proofs allow verifying that a specific image and its annotations are part of a verified dataset version without downloading or scanning the entire dataset.

### 14.1 Proof Data Model
```python
class ProofStepDirection(str, Enum):
    LEFT = "left"    # Sibling is on the left; current node is on the right
    RIGHT = "right"  # Sibling is on the right; current node is on the left

class MerkleProofStep(BaseModel):
    sibling_hash: str = Field(..., regex="^[0-9a-f]{64}$")
    direction: ProofStepDirection

class MerkleInclusionProof(BaseModel):
    proof_version: str = "1.0"
    dataset_merkle_root: str = Field(..., regex="^[0-9a-f]{64}$")
    leaf_index: int = Field(..., ge=0)
    total_leaves: int = Field(..., ge=1)
    sample_path: str
    leaf_hash: str = Field(..., regex="^[0-9a-f]{64}$")
    audit_path: List[MerkleProofStep]
```

### 14.2 Proof Verification Algorithm
Given leaf hash $H_{\text{current}}$, audit path $[S_0, S_1, \dots, S_{d-1}]$, and expected $\text{root}$:

1. Let $V = \text{bytes.fromhex}(H_{\text{current}})$.
2. For each step $S$ in audit path:
   - Let $W = \text{bytes.fromhex}(S.\text{sibling\_hash})$.
   - If $S.\text{direction} == \text{RIGHT}$:
     $$V = \text{SHA-256}\left(\text{0x01} \parallel V \parallel W\right)$$
   - Else ($S.\text{direction} == \text{LEFT}$):
     $$V = \text{SHA-256}\left(\text{0x01} \parallel W \parallel V\right)$$
3. Verify that $V.\text{hex}() == \text{dataset\_merkle\_root}$ using constant-time comparison.
4. Return `True` if valid, `False` otherwise.

---

## 15. Reproducibility & Invariants Matrix

| Scenario / Mutation | `raw_image_sha256` | `decoded_rgb_sha256` | `annotation_set_hash` | `sample_fingerprint` | `dataset_merkle_root` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Identical Dataset Re-Scan** | Unchanged | Unchanged | Unchanged | Unchanged | Unchanged |
| **EXIF / Metadata Stripping (Lossless)** | **Changes** | Unchanged | Unchanged | **Changes** | **Changes** |
| **1-Pixel Color Tweak** | **Changes** | **Changes** | Unchanged | **Changes** | **Changes** |
| **Bounding Box Shift (+1 px)** | Unchanged | Unchanged | **Changes** | **Changes** | **Changes** |
| **Category Label Renamed** | Unchanged | Unchanged | **Changes** | **Changes** | **Changes** |
| **Annotation Ordering Swapped** | Unchanged | Unchanged | Unchanged | Unchanged | Unchanged |
| **Sample File Renamed** | Unchanged | Unchanged | Unchanged | **Changes** | **Changes** |
| **New Sample Added** | Unchanged | Unchanged | Unchanged | (New Sample) | **Changes** |
| **Sample Deleted** | Unchanged | Unchanged | Unchanged | (Deleted) | **Changes** |

---

## 16. Scalability & Streaming Architecture

For datasets containing up to $100,000+$ samples:

1. **Chunked Hashing:** Raw images are hashed in 64 KiB chunks ($O(1)$ memory).
2. **Streaming Pixel Decoding:** Image pixel buffers are loaded and converted one at a time and deallocated immediately ($O(W \times H)$ peak memory).
3. **Leaf Generation Pipeline:** Produces a flat array of 32-byte leaf hashes ($100,000 \text{ samples} \times 32 \text{ bytes} \approx 3.2 \text{ MB}$ RAM).
4. **Tree Construction:** Binary tree construction over $3.2\text{ MB}$ takes $< 50\text{ ms}$ in Python.
5. **Batch Processing:** Implements a default batch size of 500 samples for pipeline throughput and status reporting.

---

## 17. Security Threat Model

| Threat | Attack Vector | Mitigation in Phase 5.3 |
| :--- | :--- | :--- |
| **Second Preimage Attack** | Craft internal node colliding with leaf node | Domain separation: `0x00` prefix for leaves, `0x01` for internal nodes |
| **Merkle Tree Duplication Attack** | Duplicate odd leaves (CVE-2012-2459) | RFC 6962 balanced power-of-2 splitting algorithm |
| **Coordinate Drift / Precision Noise** | Sub-micron float discrepancies across OS | 4-decimal place fixed quantization + RFC 8785 IEEE-754 JCS canonicalization |
| **Path Traversal / Escape** | Escaping dataset sandbox with `../` or symlinks | Phase 5.2 path security validator rejecting escapes |
| **Cross-Type Hash Confusion** | Swapping an annotation hash for a sample hash | Explicit domain separation tags on all structured payloads |
| **Inclusion Proof Forgery** | Submitting forged sibling hashes | Cryptographic preimage resistance of SHA-256 and constant-time verification |

---

## 18. Database & Phase 4 Integration Design

### 18.1 Database Impact (Zero Schema Mutations)
- Existing `SampleModel` already possesses: `file_hash_sha256`, `annotation_json`, `metadata_json`.
- Existing `DatasetVersionModel` already possesses: `dataset_hash`, `manifest_json`, `sample_count`.
- No new columns or tables are created in Phase 5.3.

### 18.2 Future Phase 4 Provenance Binding (Design Only)
In future Phase 5.9, the `dataset_hash` and `dataset_merkle_root` will be bound to an immutable `ProvenanceRecordModel` signed by the active Ed25519 system key:
```json
{
  "action": "DATASET_FINGERPRINTED",
  "target_type": "DATASET_VERSION",
  "target_id": "ver-001",
  "input_hash": "dataset_merkle_root...",
  "output_hash": "dataset_hash...",
  "metadata_json": {
    "fingerprint_version": "1.0",
    "sample_count": 5000,
    "merkle_root": "..."
  }
}
```

---

## 19. Comprehensive Testing Strategy for Phase 5.3

When implementing Phase 5.3, the following dedicated test categories will be executed:

1. **Known Answer Vectors:** Standard test vectors for domain tags and empty tree root.
2. **Raw File Reproducibility:** Streaming 64 KiB chunks produces identical hashes to complete file reads.
3. **Decoded Pixel Invariance:** PNG vs BMP with identical pixels produce identical `decoded_rgb_sha256`.
4. **Metadata Modification Test:** Stripping EXIF tags changes `raw_image_sha256` but preserves `decoded_rgb_sha256`.
5. **Annotation Order Invariance:** Shuffling annotation list produces identical `annotation_set_hash`.
6. **Coordinate Sensitivity:** Moving bounding box by 0.001 changes `annotation_set_hash`.
7. **Empty Dataset Merkle Tree:** 0 leaves yields deterministic empty root constant.
8. **Single Leaf Merkle Tree:** 1 leaf correctly computes root = leaf.
9. **Odd Leaf Merkle Trees:** $N = 3, 5, 7, 9$ correctly construct balanced trees without node duplication.
10. **Inclusion Proof Generation & Verification:** Valid proofs verify to true.
11. **Inclusion Proof Tampering:** Altered sibling hash, swapped direction, or modified leaf hash rejects with false.
12. **Full Pipeline End-to-End:** Ingesting COCO, YOLO, and ImageFolder datasets and computing complete Merkle roots.
13. **Offline Guarantee:** Network isolation test confirming zero external connections.

---

## 20. Implementation Roadmap for Phase 5.3

- **Sub-Phase 5.3.2:** Implement `backend/aivara/dataset/fingerprinting/raw.py` (Streaming raw file SHA-256).
- **Sub-Phase 5.3.3:** Implement `backend/aivara/dataset/fingerprinting/pixels.py` (Decoded RGB streaming buffer SHA-256).
- **Sub-Phase 5.3.4:** Implement `backend/aivara/dataset/fingerprinting/annotations.py` (JCS annotation set hash).
- **Sub-Phase 5.3.5:** Implement `backend/aivara/dataset/fingerprinting/sample.py` (Canonical sample fingerprint).
- **Sub-Phase 5.3.6:** Implement `backend/aivara/dataset/fingerprinting/merkle.py` (RFC 6962 binary Merkle tree, roots, and inclusion proofs).
- **Sub-Phase 5.3.7:** Implement integration pipeline orchestrator in `backend/aivara/dataset/fingerprinting/engine.py`.
- **Sub-Phase 5.3.8:** Build comprehensive automated test suite `tests/test_fingerprinting_merkle.py`.
