# AIVARA — Near-Duplicate Detection Engine Architecture Specification
## Phase 5.4: Near-Duplicate Detection & Perceptual Indexing

**Version:** 1.0.0  
**Status:** IMPLEMENTATION COMPLETE  
**Security Classification:** Local / Air-Gapped Assurance Engine  
**Target Sub-System:** Phase 5.4 — Near-Duplicate Detection Engine (NDDE)  

---

## 1. Executive Summary & Semantic Principles

The **Near-Duplicate Detection Engine (NDDE)** identifies visually and structurally near-identical image samples across datasets where raw cryptographic digests (SHA-256) differ due to re-encoding, container conversions, EXIF metadata alterations, subtle resizing, or minor compression artifacts.

### Strict Semantic Principle: NEAR-DUPLICATE ≠ MALICIOUS
Near-duplicate samples frequently arise legitimately in computer vision datasets (e.g., burst captures, video frame extractions, multi-crop data augmentation, cross-camera observations). 
- The NDDE produces **objective perceptual similarity evidence and cluster graphs**.
- The NDDE **NEVER** declares samples "malicious", "poisoned", or "adversarially tainted".
- Culpability, maliciousness, and risk assessment are strictly reserved for downstream evidence aggregation (Phase 5.8) and the executive Risk Engine (Phase 8).

---

## 2. Perceptual Hashing Algorithms

### 2.1 pHash (Perceptual Hash via 2D Discrete Cosine Transform)
- **Output:** 64-bit unsigned integer (16-character lowercase hexadecimal string).
- **Preprocessing:**
  1. EXIF orientation transposition (`ImageOps.exif_transpose`).
  2. Alpha transparency flattening over solid opaque white `(255, 255, 255)`.
  3. Conversion to canonical 8-bit grayscale (`L`).
  4. Resizing to $32 \times 32$ pixels using Bilinear interpolation.
- **2D DCT-II Transformation:**
  - Extracts the top-left $8 \times 8$ low-frequency frequency block $D_{8 \times 8} = T \cdot F \cdot T^T$.
  - Uses precomputed 1D DCT-II transformation matrix $T_{8 \times 32}$.
- **Binarization:**
  - Computes median of the 64 low-frequency coefficients.
  - Bit $i$ is `1` if $D[i] > \text{median}$ else `0`.
- **Invariance:** Highly resistant to JPEG compression, minor color balance shifts, and gamma corrections.

### 2.2 dHash (Difference Hash via Spatial Gradients)
- **Output:** 64-bit unsigned integer (16-character lowercase hexadecimal string).
- **Preprocessing:** Same normalization pipeline as pHash, resized to $9 \times 8$ (9 columns, 8 rows).
- **Gradient Comparison:**
  - For each row $y \in [0, 7]$ and column $x \in [0, 7]$:
    $$\text{bit} = 1 \quad \text{if} \quad P(x+1, y) > P(x, y) \quad \text{else} \quad 0$$
- **Invariance:** Extremely sensitive to edge directions and spatial gradients; complements frequency-domain pHash.

---

## 3. Fast Metric Distance & Candidate Indexing

### 3.1 Hamming Distance Acceleration
- Computed via bitwise XOR and hardware POPCNT instruction (`(a ^ b).bit_count()`).
- Yields integer distance $d \in [0, 64]$ in $< 20\text{ nanoseconds}$.

### 3.2 BK-Tree Metric Space Indexing
To prevent naive $O(N^2)$ all-pairs comparisons for large datasets:
- **Index Structure:** Burkhard-Keller Tree where nodes store samples and edges represent discrete Hamming distances $d \in [1, 64]$.
- **Triangle Inequality Pruning:**
  - For query $Q$, node $P$, and radius $r$:
    $$\text{Search child at edge } k \iff d(Q, P) - r \le k \le d(Q, P) + r$$
- **Pruning Efficiency:** Reduces search space significantly below $O(N^2)$ for typical dataset distributions.

### 3.3 Multi-Index Hashing (MIH)
- Partitions 64-bit hash into 4 sub-blocks of 16 bits each.
- Inverted tables index exact 16-bit matches, pruning candidates in $O(1)$ dictionary lookups prior to exact distance verification.

---

## 4. Dual-Hash Matching & Clustering

### 4.1 Configurable Match Strategies
1. **`MATCH_BOTH` (Default):** Both pHash distance $\le T_p$ (default 10) AND dHash distance $\le T_d$ (default 10).
2. **`MATCH_ANY`:** Either pHash distance $\le T_p$ OR dHash distance $\le T_d$.
3. **`WEIGHTED`:** Composite score $S = 0.6 \cdot (1 - d_p/64) + 0.4 \cdot (1 - d_d/64) \ge S_{\min}$ (default 0.84).

### 4.2 Deterministic Connected-Component Clustering
- Pairwise relationships form undirected graph edges between sample nodes.
- Breadth-First Search (BFS) identifies connected components.
- Deterministic Cluster Identifier:
  $$\text{cluster\_id} = \text{"cluster\_"} \parallel \min(\text{sample\_ids}) \parallel \text{"\_"} \parallel \text{SHA-256}(\text{joined\_sample\_ids})[:12]$$
- Contributors associated with member samples are unified and preserved for Phase 5.8 aggregation.

---

## 5. Offline Guarantees & Resource Safety
- **100% Offline:** Zero external network calls, cloud API lookups, or runtime model downloads.
- **Memory Safety:** Operates on compact 64-bit perceptual hashes (8 bytes per sample in index), discarding pixel buffers immediately.
- **Deterministic Collation:** Independent of filesystem directory enumeration order.
