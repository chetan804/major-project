# EcoMind-AI — AI/ML Architecture

**Status:** Phase 0 baseline
**Related:** `model-registry.md`, `model-cards.md`, `assistant-safety.md`,
`../architecture/decisions.md` (ADR-0008, ADR-0009, ADR-0010), `../architecture/domain-model.md` §7

---

## 1. Where AI is and is not used

The master specification forbids using an LLM as a substitute for
authentication, authorization, numerical optimization, database constraints,
validation, deterministic business rules, or safety-critical logic (section 25),
and requires deterministic algorithms where determinism is more appropriate
(section 24). EcoMind-AI therefore splits work by method suitability:

| Decision to make | Method | Why not the alternative |
|---|---|---|
| Which bins need collection first? | **Deterministic weighted scoring** (`scoring_configurations`) | Must be explainable to a dispatcher and identical for identical inputs. |
| What route minimises cost under capacity/time-window constraints? | **OR-Tools CVRPTW** | NP-hard combinatorial optimization; an LLM cannot guarantee feasibility or optimality. |
| How much waste tomorrow? | **Statistical/ML forecasting** (seasonal naive → exponential smoothing → gradient-boosted trees) | Requires calibrated uncertainty; LLMs cannot produce calibrated intervals. |
| What waste is in this photo? | **Computer vision classifier** (pluggable backend) | Needs a measured confusion matrix and reproducible inference. |
| Is this reading abnormal? | **Interpretable statistics** (z-score/IQR/moving baseline), Isolation Forest only when justified | Must be explainable to an operator and cheap to run at scale. |
| How much CO₂e did that route emit? | **Versioned emission factors × measured activity** | Arithmetic over auditable inputs; no model may invent a factor. |
| "Summarise today's problems and what to investigate" | **LLM assistant over permission-checked tools** | Language is where an LLM genuinely helps — and only for language. |
| Anything involving auth, permissions, validation, state transitions | **Never AI** | Forbidden by section 25; these are enforced in code and in the database. |

The guiding rule: **AI is used where the output is language or a statistical
estimate; determinism is used where the output is a decision with operational or
safety consequences.**

---

## 2. Model registry

Implemented as tables (`ai_models`, `ai_model_versions`, `ml_datasets`,
`model_metrics` — ERD §8) plus a service layer. Requirements satisfied:

* **Versioned models** with an immutable `feature_definition` and an artifact
  checksum.
* **Exactly one ACTIVE version per model**, enforced by a partial unique index
  (BR-14) — not by convention.
* **Promotion requires metrics.** The service refuses to set `status='ACTIVE'`
  on a version with no `model_metrics` rows for a non-training evaluation type.
* **Rollback** re-activates the previous version and records the actor; because
  versions are immutable, rollback is a pointer change, never a re-training.
* **Dataset provenance.** Every metric row references an `ml_datasets` row that
  carries `is_synthetic` and, for synthetic data, the generation parameters
  including the seed. `evaluation_type='TRAINING'` metrics are stored but are
  never presented as validation performance (section 49).
* **States:** `CANDIDATE → ACTIVE → RETIRED`, plus `FAILED`. Deep-learning
  models may only ever be `CANDIDATE` until trained and evaluated on a real
  labelled corpus.

---

## 3. Forecasting subsystem

**Pipeline:** `ForecastRun` (job) → load historical series for the subject →
build features → fit/apply the selected model → persist `Forecast` rows with
uncertainty → record metrics when the horizon later materialises (backtest) →
optionally emit an anomaly or recommendation.

**Baseline-first policy.** The platform always computes the *seasonal naive*
baseline alongside the chosen model, because a forecasting system that cannot
beat "same time last week" has no business being deployed:

| Order | Model | When it is the right choice |
|---|---|---|
| 1 | Seasonal naive (`baseline_value` on every forecast) | Always computed; the comparison floor. |
| 2 | Moving average / exponential smoothing (`EXPONENTIAL_SMOOTHING`) | Short histories (< ~8 weeks), noisy data. |
| 3 | Gradient-boosted trees (`GBT_REGRESSOR`) | ≥ ~12 weeks of history; calendar/zone/weather features available. |
| 4 | Sequence models (deep learning) | **Not implemented** — would require much more data than a tenant realistically has at onboarding. Documented as a future extension point, not a claim. |

**Features** (documented in `feature_definition`, stored per run):
lags (t-1, t-7, t-14, t-28), rolling means/stds (7/14/28), day-of-week and
month indicators, holiday flag (configurable calendar), zone characteristics
(population, area, service frequency), sensor coverage ratio, optional weather
(labelled when the synthetic provider is used), and trend terms.

**Mandatory metadata on every forecast:** `predicted_value`, `lower_bound`,
`upper_bound`, `confidence_level`, `horizon_step`, `forecast_for`,
`forecast_run_id` → model version → `training_dataset_id` → input window.
Uncertainty is produced empirically from **backtest residuals** (per-horizon
error quantiles), not from an assumption of normality; if a subject has too few
residuals to estimate intervals, the interval is `null` and the API returns
`uncertainty_available: false` rather than a made-up band.

**Evaluation:** MAE, RMSE, MAPE (guarded against zero denominators, which yield
`null` + reason), R², and a **per-horizon-step breakdown**, plus baseline
comparison. Backtesting uses rolling-origin evaluation on held-out periods; the
evaluation window never overlaps training.

**Failure behaviour:** insufficient history → `INSUFFICIENT_DATA` with the
required-versus-available counts; model artifact missing → the run fails with a
clear error and the API returns `DEPENDENCY_UNAVAILABLE`, never a silent
fallback to a different model without recording that substitution.

---

## 4. Anomaly detection

| Method | Applied to | Parameters (stored per anomaly) |
|---|---|---|
| Rolling z-score | fill %, weight, temperature, battery, fuel | window, z-threshold (default 3.0), min samples |
| IQR fences | same, for skewed distributions | window, k (default 1.5) |
| Moving baseline | inter-collection interval, daily volume per bin/zone | window, tolerance % |
| Isolation Forest | multivariate sensor drift (only when univariate methods demonstrably miss drift) | n_estimators, contamination, feature list |

Each anomaly stores method, parameters, baseline window, score, threshold,
severity and a human-readable explanation string. Severity maps to notification
severity. Operators can mark false positives — that feedback is retained
(`anomalies.status='FALSE_POSITIVE'`) and reported, so detection quality is
observable rather than asserted. Suppression rules (e.g. ignore battery alerts
right after a maintenance record) prevent alert fatigue; every suppression is
logged with its reason.

**Deliberate anti-patterns avoided:** no anomaly is reported without a baseline
window (otherwise "anomaly" is meaningless); no anomaly triggers an irreversible
action — at most it opens an alert or a recommendation.

---

## 5. Waste classification (computer vision)

### 5.1 Interface

```python
class ClassificationBackend(Protocol):
    name: str
    version: str
    supported_categories: list[str]

    def predict(self, image: np.ndarray) -> ClassificationResult: ...  # top-k + timing
    def warmup(self) -> None: ...
    def health(self) -> BackendHealth: ...
```

Implementations: `ClassicalCVBackend` (default), `TorchvisionBackend`
(`requirements/vision.txt`), `ManualBackend` (human labelling, provenance
`USER_ENTERED`). Selection is configuration (`CLASSIFICATION_BACKEND`), never a
branch inside business logic.

### 5.2 Pipeline (real, end to end)

```
upload → file validation (magic bytes, size, dimensions, decode test)
      → preprocessing (EXIF rotate, resize, normalise, denoise)
      → feature extraction / tensor prep
      → backend.predict() → top-k labels + confidence
      → persist waste_classifications (+ model_version, inference_ms, image_hash)
      → if confidence < CLASSIFICATION_REVIEW_THRESHOLD → needs_review = true
      → human review → classification_feedback (closed loop)
      → metrics aggregation → model card
```

### 5.3 The classical backend, honestly described

Features: colour moments and HSV histograms, edge density (Canny), texture via
local-binary-pattern histograms, shape/size statistics of segmented regions, and
coarse spatial layout. Model: a scikit-learn classifier (logistic regression /
random forest) selected by cross-validated comparison.

**Training data:** a deterministic, seeded **synthetic** corpus generated by
`ml/datasets/synthetic_waste.py`. Each class is rendered from documented
per-class colour/texture/layout distributions (e.g. glass = high brightness,
low saturation, high specular edges; organic = brown/green, high texture
entropy). The generator is versioned and its seed and parameters are stored in
`ml_datasets.generation_parameters`.

**Claim discipline.** The measured metrics are published verbatim in
`model-cards.md` together with this statement: *metrics on a synthetic corpus
validate the pipeline and the metric computation; they are not evidence of field
accuracy.* The model is registered with `is_synthetic=true` and its
`evaluation_type='SYNTHETIC_BENCH'`. No dashboard, report or API response
presents these numbers as real-world accuracy.

**Low-confidence handling (BR-15):** below-threshold results are queued for
review and are **never** used to drive hazardous-waste handling. A hazardous
classification additionally requires either confidence above a higher
hazard-specific threshold or human confirmation. This is enforced in the
service that consumes classifications, not merely in the UI.

### 5.4 Evaluation pipeline

`ml/evaluation/classification_metrics.py` computes accuracy, per-class
precision/recall/F1, macro/weighted averages, the confusion matrix, and the
full metric set for any labelled dataset — used both on the synthetic corpus and
on any future real corpus. Results are written to `model_metrics` (never
hardcoded). A `docs/ai/model-cards.md` entry is generated per version. Metrics
are computed on a held-out split; the split is recorded.

---

## 6. Route optimization (deterministic — not an LLM)

Detail in `../architecture/domain-model.md` §7 and `../architecture/decisions.md`
ADR-0007. AI-relevant points:

* The solver is invoked as a **background job**; the API returns `202` with a run
  id, so a large instance cannot hang a request.
* Objective = weighted sum of travel distance, vehicle count, and priority
  penalties for unassigned high-priority stops; weights come from the request and
  are stored in the run, so "why did it choose this?" is answerable.
* The run records `is_optimal`: if the time limit was reached, the platform says
  so rather than implying optimality.
* Unassigned stops are returned with reasons (capacity, time window, priority),
  which is what makes the result actionable instead of a black box.
* Applying a result is a separate, permission-checked, audited human action.

---

## 7. AI recommendations

Generated by a **rule engine over computed metrics** (not by free-form LLM
generation), which is what makes BR-16's evidence requirement natural:

| Type | Trigger examples | Evidence attached |
|---|---|---|
| `COLLECTION_PRIORITY` | ≥N bins with priority above threshold | bin ids, scores, factor breakdowns |
| `OVERFLOW_PREVENTION` | overflow-risk ≥ 0.75 for ≥N bins in a zone within 24 h | bin ids, probabilities, model version |
| `ROUTE_OPTIMIZATION` | recent routes with utilization < 60 % or distance above zone median | route ids, metrics, comparison values |
| `MAINTENANCE` | sensor offline > threshold, or anomaly cluster on a vehicle | device/vehicle ids, uptime stats |
| `FACILITY_REBALANCE` | facility utilization > 85 % with a peer below 50 % | facility ids, intake stats |
| `CAPACITY_PLANNING` | sustained forecast growth > X % over 8 weeks | forecast run id, intervals |
| `FUEL_REDUCTION` | route efficiency below baseline, or excessive idling signals | route metrics, estimated deltas |
| `ANOMALY_INVESTIGATION` | anomaly cluster severity high | anomaly ids, method, score |

Lifecycle (`NEW → VIEWED → ACCEPTED/REJECTED → EXECUTED`, plus `EXPIRED`) is
tracked with feedback, so recommendation quality becomes measurable over time.
A `CHECK` constraint guarantees the evidence array is non-empty. Recommendations
never mutate state themselves; `EXECUTED` records the operational artefact the
user created as a result.

---

## 8. The assistant (tool-bound, tenant-safe)

### 8.1 Architecture

```
user question
   → conversation context (tenant, user, permissions, recent turns)
   → LLM planner (or deterministic planner when LLM_PROVIDER=local)
        ↳ may ONLY emit tool calls validated against the registry
   → tool registry executes against the SAME services the REST API uses
        ↳ tenant context injected server-side; model cannot supply it
        ↳ each tool checks the caller's permissions before executing
   → structured results (Pydantic models, never raw rows/SQL)
   → answer synthesis: every statement bound to a tool result
   → response with statements[], evidence, tools_used[], limitations[]
```

### 8.2 Tool catalogue (controlled, minimal, structured)

`get_bin_status` · `get_bin_telemetry_summary` · `get_collection_metrics` ·
`get_collection_tasks` · `get_route_metrics` · `get_vehicle_status` ·
`get_driver_status` · `get_forecast` · `get_anomalies` ·
`get_environment_metrics` · `get_facility_status` · `get_recommendations` ·
`get_zone_statistics` · `get_waste_composition` · `get_alert_summary` ·
`search_bins` · `explain_metric`.

Tool contract rules:
1. Every tool declares a permission; the registry refuses to execute if the
   caller lacks it — identical to the REST check (`AI cannot call tools the
   underlying user cannot call`, section 28).
2. Every tool takes a **typed argument schema**; free text is never executed.
3. Every tool returns a Pydantic model with a bounded row limit, so a question
   cannot cause an unbounded scan.
4. No tool exposes raw SQL, table names, other tenants, credentials, or
   file contents. Results carry row ids for drill-down, which is how the UI
   renders "view source".
5. Read-only by construction: there is no write/destructive tool. Any action is
   returned as a *proposal* with a deep link that the user must confirm in the
   real UI (section 28/29).

### 8.3 Hallucination and injection containment

* **Grounded answers only.** The synthesis layer maps each sentence to evidence
  from the tool results. If a question cannot be answered from tool output, the
  answer is `UNKNOWN` with the reason and a suggested alternative question.
* **Untrusted content is data, never instruction.** Telemetry notes, user
  comments, imported CSV values, and uploaded/image-derived text are inserted
  into prompts only in delimited data slots, and the system prompt states that
  content inside those slots is never an instruction. Tool *arguments* are
  schema-validated before execution, so an injection cannot widen a query.
* **Tenant and permission containment.** Tenant context is server-derived and
  absent from the model-visible schema; a cross-tenant request is
  unrepresentable, and the isolation suite proves it by attempting a
  tenant-B question as tenant A through every tool.
* **Output validation.** The model's response must parse into the response
  schema; a malformed or unsupported statement type is rejected and the API
  returns a safe fallback rather than unvalidated text.
* **Rate limits and cost controls.** Per-user request caps, max tool calls per
  turn, max tokens, and a per-tenant daily budget; exceeding a limit returns a
  clear error rather than silently degrading.
* **Labels.** `DATABASE_FACT`, `MODEL_PREDICTION`, `ESTIMATE`, `RECOMMENDATION`,
  `UNKNOWN` are rendered in the UI so a reader always knows which is which
  (section 27).

### 8.4 Local deterministic provider

`LLM_PROVIDER=local` implements the same interface with a rule-based intent
router over the identical tool registry. It is not a mock: it produces genuine
answers from genuine tool output and is what runs in the sandbox, in CI, and in
offline deployments. When a hosted LLM is configured, the tool layer, permission
checks, evidence structure and safety tests are unchanged — only the language
generation improves.

---

## 9. AI testing plan

| Category | Tests |
|---|---|
| Grounding | Answers with no tool evidence are rejected; every statement maps to a tool result; unsupported questions return `UNKNOWN`. |
| Tool authorization | Each role × each tool: allowed/denied matches the permission catalogue; a viewer cannot reach write-shaped tools (none exist, asserted). |
| Tenant leakage | Tenant A asks every tool about tenant B ids → empty/`404`, never data; asserted in the isolation suite. |
| Prompt injection | Payloads embedded in bin notes, user comments, CSV imports, and image-derived text do not alter tool arguments or permissions; the assistant does not echo injected system-prompt content. |
| Structured output | Malformed provider output is rejected safely; response always validates against the schema. |
| Determinism | `LLM_PROVIDER=local` produces identical answers for identical data and seeds. |
| Model metrics | Metric computation verified against hand-computed fixtures (precision/recall/F1/confusion matrix), including edge cases (zero-division, single-class). |
| Forecasting | Backtest harness correctness; interval coverage measured and reported honestly, including the case where intervals are `null`. |
| Anomaly | Known injected anomalies are detected; known-normal series produce no false alarms at the configured threshold. |
| Boundaries | Confidence thresholds route to review; hazardous categories require the higher bar. |
