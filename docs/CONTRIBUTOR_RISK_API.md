# Contributor Risk REST API & Integration Services (Phase 6.3)

## 1. Overview

Phase 6.3 exposes the Phase 6.2 Contributor Risk domain & statistical engine through clean, deterministic, multi-tenant application services and REST APIs under `/api/v1/projects/{project_id}/contributors/`.

The service architecture strictly follows the authoritative layer hierarchy:

```
                      REST API Router
                             ↓
              ContributorRiskService (Application Layer)
                             ↓
            Phase 6.2 Contributor Risk Engine (Authoritative)
                             ↓
                Phase 5 Evidence / Findings
                             ↓
              Phase 5.9 Provenance Binding
                             ↓
             Phase 4 Cryptographic Provenance
```

---

## 2. Invariants & Architectural Decisions Preserved

1. **Zero Scalar Risk Scores (ADR-030):** The REST API never outputs scalar risk scores (e.g. `risk_score: 87`). It strictly returns structured profiles containing `detection_profile` and `proof_profile`.
2. **Authoritative Statistical Engine (ADR-031, ADR-032):** The API layer performs zero statistical calculations. All Bayesian shrinkage, Beta-Binomial modeling, empirical variance bounds, and Leave-One-Out contextual baselines remain strictly within `ContributorRiskEngine`.
3. **Database Rule (Zero Schema Changes & Sentinel Semantics):** Zero new tables, zero migrations, zero column additions. Reuses `RiskAssessmentModel` (`scope="contributor"`, `component_scores_json=profile_json`). Because `RiskAssessmentModel.overall_risk_score` is a `Float NOT NULL` column in the frozen database schema, it stores `-1.0` as an explicit, out-of-band schema compatibility sentinel for `NOT_APPLICABLE` (valid scalar risk scores in AIVARA are bounded $[0.0, 1.0]$). Contributor risk is defined and evaluated solely through the structured multidimensional profile. No scalar risk score is ever computed, assigned, or returned via the API.
4. **Strict Multi-Tenant Project Isolation:** Contributor IDs, dataset versions, findings, and evidence are project-scoped. Cross-project references deterministically return `422 Unprocessable Entity` with `CROSS_PROJECT_CONTAMINATION` error envelopes.
5. **Semantic Safety (ADR-035):** API responses and error messages contain zero unsupported intent, motive, or guilt terminology (`malicious`, `sabotage`, `guilty`, `deliberate`, `fraudulent`). Technical security terms (`adversarial perturbation`, `poisoning attack`, `backdoor trigger`) are allowed and preserved.
6. **Deterministic Idempotency:** The same input context generates identical analytical output payloads and reuses/updates the existing `RiskAssessmentModel` record without creating duplicates.
7. **Phase 5.9 & Phase 4 Provenance Sealing:** Optional provenance sealing binds the contributor assessment execution identity into the cryptographic ledger via `EvidenceProvenanceService`.

---

## 3. REST API Endpoints

All endpoints are prefixed with `/api/v1/projects/{project_id}/contributors`.

### 3.1 List Contributor Risk Profiles
- **Route:** `GET /api/v1/projects/{project_id}/contributors/risk-profiles`
- **Query Parameters:**
  - `dataset_version_id` (optional `string`): Filter or scope by dataset version.
- **Success Response (200 OK):**
  ```json
  {
    "status": "success",
    "data": [
      {
        "contributor_id": "contrib-alice",
        "project_id": "proj-alpha",
        "dataset_version_id": "ver-alpha-01",
        "effective_sample_count": 10.0,
        "support_state": "MODERATE_SUPPORT",
        "profile_status": "BASELINE_CONGRUENT",
        "detection_profile": {
          "label_reliability": {
            "evidence_layer": "detection",
            "observed_rate": 0.10,
            "shrunk_rate": 0.08,
            "differential": 0.03,
            "confidence": 0.85,
            "support_state": "MODERATE_SUPPORT",
            "evidence_ids": ["finding-label-01"],
            "limitations": []
          }
        },
        "proof_profile": {
          "provenance_integrity": {
            "evidence_layer": "proof",
            "confidence": 1.0,
            "verification_status": "VERIFIED",
            "tamper_detected": false
          }
        },
        "limitations": [],
        "created_at": "2026-09-10T08:00:00Z"
      }
    ]
  }
  ```

### 3.2 Get Contributor Risk Profile
- **Route:** `GET /api/v1/projects/{project_id}/contributors/{contributor_id}/risk-profile`
- **Query Parameters:**
  - `dataset_version_id` (optional `string`)
- **Success Response (200 OK):**
  - Returns `ApiResponse[ContributorRiskProfileRead]` for the specific contributor.

### 3.3 Create / Trigger Contributor Risk Assessment
- **Route:** `POST /api/v1/projects/{project_id}/contributors/risk-assessments`
- **Request Body (`ContributorRiskAssessmentCreate`):**
  ```json
  {
    "contributor_id": "contrib-alice",
    "dataset_version_id": "ver-alpha-01",
    "seal_provenance": true,
    "signer_key_id": "key-id-optional",
    "signer_passphrase": "passphrase-optional"
  }
  ```
- **Success Response (201 Created):**
  - Returns `ApiResponse[ContributorRiskProfileRead]` with sealed provenance status.

### 3.4 Get Contributor Baselines
- **Route:** `GET /api/v1/projects/{project_id}/contributors/{contributor_id}/baselines`
- **Query Parameters:**
  - `dataset_version_id` (optional `string`)
- **Success Response (200 OK):**
  ```json
  {
    "status": "success",
    "data": {
      "contributor_id": "contrib-alice",
      "project_id": "proj-alpha",
      "effective_exposure": 10.0,
      "support_state": "MODERATE_SUPPORT",
      "baselines": {
        "label_reliability": {
          "baseline_type": "LEAVE_ONE_OUT",
          "baseline_rate": 0.05,
          "sample_size": 20.0,
          "reference_population": "Leave-One-Out background (all contributors except Alice)"
        },
        "quality_divergence": null,
        "distribution_shift": null
      }
    }
  }
  ```

### 3.5 Get Contributor Evidence Graph
- **Route:** `GET /api/v1/projects/{project_id}/contributors/{contributor_id}/evidence-graph`
- **Query Parameters:**
  - `dataset_version_id` (optional `string`)
- **Success Response (200 OK):**
  ```json
  {
    "status": "success",
    "data": {
      "contributor_id": "contrib-alice",
      "project_id": "proj-alpha",
      "dataset_version_id": "ver-alpha-01",
      "effective_exposure": 10.0,
      "total_attributed_samples": 10,
      "attributed_samples": [
        {"sample_id": "sample-01", "contribution_type": "annotator"}
      ],
      "evidence_items": [
        {
          "evidence_id": "ev-01",
          "finding_id": "finding-01",
          "evidence_type": "label_anomaly_latent_disagreement",
          "evidence_layer": "detection",
          "confidence": 0.88,
          "evidence_hash": "..."
        }
      ],
      "findings": [
        {
          "finding_id": "finding-01",
          "finding_type": "LABEL_ANOMALY",
          "severity": "medium",
          "confidence": 0.88,
          "evidence_layer": "detection",
          "affected_sample_id": "sample-01"
        }
      ],
      "dimensions": [
        "DIM_LABEL_RELIABILITY",
        "DIM_TRANSITION_ASYM",
        "DIM_QUALITY_DIVERGENCE",
        "DIM_DISTRIBUTION_SHIFT",
        "DIM_PROVENANCE_INTEGRITY"
      ]
    }
  }
  ```

---

## 4. Error Handling & Multi-Tenant Security

All errors are returned in the unified `ApiErrorResponse` envelope:
```json
{
  "status": "error",
  "error": {
    "code": "CROSS_PROJECT_CONTAMINATION",
    "message": "Contributor 'contrib-carol' belongs to project 'proj-beta', not 'proj-alpha'.",
    "details": {}
  }
}
```

| HTTP Status | Error Code | Trigger Condition |
|---|---|---|
| `404 Not Found` | `NOT_FOUND` | Project, contributor, or dataset version does not exist. |
| `422 Unprocessable Entity` | `CROSS_PROJECT_CONTAMINATION` | Contributor or dataset version belongs to a different project. |
| `422 Unprocessable Entity` | `SEMANTIC_SAFETY_VIOLATION` | Unsupported human-intent or guilt vocabulary in input payload. |
| `400 Bad Request` | `VALIDATION_FAILED` | Request schema or payload structure validation failure. |
