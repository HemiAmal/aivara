# Phase 11.10: API Contracts & Schemas Specification

## 1. Request Schemas

```python
class DriftAnalysisTypeEnum(str, Enum):
    """Canonical analysis types supported by the distribution shift subsystem."""
    DATASET = "DATASET"
    FEATURE = "FEATURE"
    IMAGE = "IMAGE"
    REPRESENTATION = "REPRESENTATION"
    TEMPORAL = "TEMPORAL"
    SOURCE = "SOURCE"
    MULTIMODAL = "MULTIMODAL"


class TemporalAnalysisConfig(BaseModel):
    """Configuration for temporal windowed drift evaluation."""
    model_config = ConfigDict(extra="forbid")
    window_strategy: str = Field(default="FIXED_INTERVAL")
    window_duration_seconds: Optional[float] = Field(default=86400.0, ge=60.0)
    comparison_topology: str = Field(default="BASELINE_AND_ADJACENT")
    max_windows: int = Field(default=50, ge=2, le=50)


class SourceAnalysisConfig(BaseModel):
    """Configuration for contributor and source-aware drift evaluation."""
    model_config = ConfigDict(extra="forbid")
    source_metadata_key: str = Field(default="source_group_id", min_length=1, max_length=100)
    max_source_groups: int = Field(default=50, ge=2, le=50)
    evaluate_simpsons_confounding: bool = Field(default=True)


class RepresentationAnalysisConfig(BaseModel):
    """Configuration for embedding / representation drift evaluation."""
    model_config = ConfigDict(extra="forbid")
    embedding_dimension: int = Field(default=384, ge=1, le=4096)
    statistical_method: str = Field(default="KERNEL_MMD")
    permutation_iterations: int = Field(default=100, ge=10, le=100)
    l2_normalize: bool = Field(default=True)


class MultiModalAssuranceConfig(BaseModel):
    """Configuration for multi-modal risk synthesis."""
    model_config = ConfigDict(extra="forbid")
    correlation_damping_factor: float = Field(default=0.10, ge=0.0, le=0.50)
    review_threshold: float = Field(default=0.30, ge=0.0, le=1.0)
    quarantine_threshold: float = Field(default=0.65, ge=0.0, le=1.0)
    reject_threshold: float = Field(default=0.85, ge=0.0, le=1.0)


class DriftAnalysisCreateRequest(BaseModel):
    """Request payload to initiate distribution shift analysis."""
    model_config = ConfigDict(extra="forbid")

    reference_dataset_id: str = Field(..., min_length=1, max_length=64)
    reference_dataset_version_id: Optional[str] = Field(default=None, max_length=64)
    target_dataset_id: str = Field(..., min_length=1, max_length=64)
    target_dataset_version_id: Optional[str] = Field(default=None, max_length=64)
    analysis_type: DriftAnalysisTypeEnum = Field(default=DriftAnalysisTypeEnum.DATASET)
    feature_names: Optional[List[str]] = Field(default=None)
    alpha_significance: float = Field(default=0.05, gt=0.0, lt=1.0)
    effect_size_threshold: Optional[float] = Field(default=None, gt=0.0)
    sample_budget: int = Field(default=5000, ge=30, le=5000)
    idempotency_key: Optional[str] = Field(default=None, max_length=64)
    temporal_config: Optional[TemporalAnalysisConfig] = None
    source_config: Optional[SourceAnalysisConfig] = None
    representation_config: Optional[RepresentationAnalysisConfig] = None
    multimodal_config: Optional[MultiModalAssuranceConfig] = None
```

---

## 2. Response Schemas

```python
class DriftTaskStatusEnum(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class DriftTaskResponse(BaseModel):
    """Response returned upon submitting or polling a drift analysis task."""
    model_config = ConfigDict(extra="ignore")

    task_id: str
    project_id: str
    analysis_type: DriftAnalysisTypeEnum
    status: DriftTaskStatusEnum
    progress_percent: float
    current_stage: str
    stage_description: Optional[str] = None
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    idempotency_key: Optional[str] = None


class DriftFeatureSummaryItem(BaseModel):
    """Summary of drift evaluation for a single feature or dimension."""
    model_config = ConfigDict(extra="ignore")

    feature_name: str
    feature_type: str
    statistical_method: str
    statistic_value: float
    p_value: float
    p_value_adjusted: float
    is_drift_detected: bool
    drift_impact_level: str


class DriftAnalysisResultResponse(BaseModel):
    """Authoritative complete result of a distribution shift analysis."""
    model_config = ConfigDict(extra="ignore")

    task_id: str
    project_id: str
    analysis_type: DriftAnalysisTypeEnum
    reference_dataset_id: str
    target_dataset_id: str
    evaluation_status: str
    overall_disposition: str
    normalized_operational_exposure_index: float
    risk_level: str
    features_evaluated_count: int
    features_drifted_count: int
    feature_summaries: List[DriftFeatureSummaryItem] = Field(default_factory=list)
    boundary_hash: str
    analysis_result_hash: str
    integrated_profile_hash: Optional[str] = None
    provenance_record_id: Optional[str] = None
    findings_count: int = 0
    evidence_count: int = 0
    rationale: str
    limitations: List[str] = Field(default_factory=list)
    executed_at: str


class DriftProgressEvent(BaseModel):
    """Real-time Server-Sent Event broadcast payload."""
    model_config = ConfigDict(extra="ignore")

    sequence_number: int
    event_id: str
    task_id: str
    stage: str
    progress_percent: float
    message: str
    timestamp: str
    payload: Optional[Dict[str, Any]] = None


class DriftCapabilitiesResponse(BaseModel):
    """Descriptors of supported subsystem capabilities."""
    model_config = ConfigDict(extra="ignore")

    api_version: str = "1.0.0"
    schema_version: str = "1.0"
    supported_analysis_types: List[str]
    supported_statistical_methods: List[str]
    max_sample_budget: int = 5000
    min_sample_floor: int = 30
    max_embedding_dimension: int = 4096
    max_temporal_windows: int = 50
    max_source_groups: int = 50
```
