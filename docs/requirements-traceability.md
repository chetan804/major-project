# EcoMind-AI — Requirements Traceability Matrix

**Status:** Phase 0 skeleton — every requirement has a *designed* home before code exists.
**Update rule:** a requirement's `Status` advances only when its `Tests` column
points at tests that actually pass. Rows are never deleted; unimplemented work
stays visible as `PLANNED`.

**Status vocabulary:** `DESIGNED` (Phase 0 complete) · `IN PROGRESS` ·
`IMPLEMENTED` (code + tests + docs) · `DEFERRED` (with reason) · `OUT OF SCOPE`
(with reason).

Legend for `Impl` column: module paths are relative to `backend/app/` unless
otherwise noted.

---

## 1. Platform and architecture

| Req | Requirement | Subsystem | Impl | API | DB | Tests | Doc | Status |
|---|---|---|---|---|---|---|---|---|
| REQ-PLT-001 | Multi-tenant SaaS with enforced isolation | tenancy | `core/tenancy.py`, `repositories/base.py` | all | `tenants`, RLS on all tenant tables | `security/test_tenant_isolation.py` | `architecture/architecture.md` §5 | DESIGNED |
| REQ-PLT-002 | Modular monolith with enforceable boundaries | all | module layout + import rules | — | — | `architecture/test_import_rules.py` | `architecture/architecture.md` §3 | DESIGNED |
| REQ-PLT-003 | Versioned REST API + OpenAPI | api | `api/v1/*` | `/api/v1/*` | — | `api/test_openapi_contract.py` | `api/rest-api.md` | DESIGNED |
| REQ-PLT-004 | Standard error contract, no internal leakage | core | `core/errors.py` | all | — | `api/test_error_contract.py` | `api/error-catalogue.md` | DESIGNED |
| REQ-PLT-005 | UUID PKs, UTC timestamps, NUMERIC for measured values | db | model mixins | — | all tables | `db/test_decimal_precision.py` | `database/erd.md` §1 | DESIGNED |
| REQ-PLT-006 | Alembic migrations, no manual DDL | db | `migrations/` | — | all | `db/test_migrations.py` | `deployment/migrations.md` | DESIGNED |
| REQ-PLT-007 | Auditability of important mutations | audit | `services/audit.py` | `/audit-logs` | `audit_logs` | `services/test_audit.py` | `security/security-model.md` §8 | DESIGNED |
| REQ-PLT-008 | Observability: health, readiness, metrics, request ids | observability | `core/logging.py`, `api/health.py` | `/health`, `/ready`, `/metrics` | — | `api/test_health.py` | `architecture/architecture.md` §10 | DESIGNED |
| REQ-PLT-009 | Background jobs, idempotent and observable | workers | `workers/registry.py` | `/jobs` | `job_runs` | `jobs/test_idempotency.py` | `architecture/decisions.md` ADR-0009 | DESIGNED |
| REQ-PLT-010 | Selective caching with tenant-safe keys | core | `core/cache.py` | — | — | `core/test_cache_keys.py` | `architecture/architecture.md` §12 | DESIGNED |
| REQ-PLT-011 | Environment-based configuration, no secrets in Git | core | `core/config.py` | — | — | `tests/test_no_secret_leakage.py` | `.env.example`, `deployment/configuration.md` | DESIGNED |
| REQ-PLT-012 | i18n-ready frontend strings | frontend | `i18n/` | — | `notification_templates` | frontend lint rule | `frontend/information-architecture.md` §1 | DESIGNED |
| REQ-PLT-013 | Timezone-correct handling (UTC storage, local presentation) | core | `core/time.py` | — | `TIMESTAMPTZ` | `core/test_timezone.py` | `architecture/domain-model.md` BR-18 | DESIGNED |

## 2. Identity, access and security

| Req | Requirement | Subsystem | Impl | API | DB | Tests | Doc | Status |
|---|---|---|---|---|---|---|---|---|
| REQ-AUTH-001 | Registration, login, logout, session management | identity | `services/auth.py` | `/auth/*` | `users`, `sessions` | `auth/test_login_flow.py` | `security/security-model.md` §2 | DESIGNED |
| REQ-AUTH-002 | Argon2id password hashing + policy | identity | `core/security.py` | `/auth/password/*` | `users.password_hash` | `auth/test_password_policy.py` | `security/security-model.md` §2 | DESIGNED |
| REQ-AUTH-003 | Refresh-token rotation with reuse detection | identity | `services/session.py` | `/auth/refresh` | `sessions.family_id` | `auth/test_token_lifecycle.py` | `security/security-model.md` §2 | DESIGNED |
| REQ-AUTH-004 | Password reset + email verification architecture | identity | `services/account_recovery.py` | `/auth/password/reset-*` | `users.email_verified_at` | `auth/test_recovery_flows.py` | `security/security-model.md` §2 | DESIGNED |
| REQ-AUTH-005 | Session revocation and account status gating | identity | `services/session.py` | `/auth/sessions` | `sessions.revoked_at` | `auth/test_session_revocation.py` | `security/security-model.md` §2 | DESIGNED |
| REQ-AUTH-006 | Granular RBAC with 10 tenant roles + platform role | authorization | `authorization/*` | `/roles`, `/permissions` | `roles`, `permissions`, `role_permissions`, `user_roles` | `security/test_authorization_matrix.py` | `security/rbac.md` | DESIGNED |
| REQ-AUTH-007 | Backend-enforced authorization; frontend guards supplementary | authorization | dependencies + service guards | all | — | `security/test_authorization_matrix.py` | `security/rbac.md` §1.1 | DESIGNED |
| REQ-AUTH-008 | Never trust client-supplied tenant/user/role | tenancy | `core/tenancy.py` | all | RLS | `security/test_tenant_isolation.py` | `architecture/decisions.md` ADR-0004 | DESIGNED |
| REQ-SEC-001 | Input validation, mass-assignment prevention | core | Pydantic schemas | all | CHECK constraints | `api/test_mass_assignment.py` | `security/security-model.md` §5 | DESIGNED |
| REQ-SEC-002 | SQL-injection resistance | db | SQLAlchemy only | all | — | `security/test_injection.py` | `security/security-model.md` §5 | DESIGNED |
| REQ-SEC-003 | Rate limiting on sensitive endpoints | core | `core/ratelimit.py` | all | — | `security/test_rate_limits.py` | `security/security-model.md` §1 T9 | DESIGNED |
| REQ-SEC-004 | CORS + security headers + CSRF strategy | api | middleware | all | — | `security/test_security_headers.py` | `security/security-model.md` §7 | DESIGNED |
| REQ-SEC-005 | File-upload validation and safe storage | files | `services/files.py` | `/files/*` | `file_assets` | `security/test_file_upload.py` | `security/security-model.md` §6 | DESIGNED |
| REQ-SEC-006 | Secret management, no secrets in source | core | `core/config.py` | — | — | `scripts/check_secrets.py` | `deployment/configuration.md` | DESIGNED |
| REQ-SEC-007 | Audit trail of security-relevant events | audit | `services/audit.py` | `/audit-logs` | `audit_logs` | `security/test_audit_events.py` | `security/security-model.md` §8 | DESIGNED |

## 3. Waste domain, IoT and operations

| Req | Requirement | Subsystem | Impl | API | DB | Tests | Doc | Status |
|---|---|---|---|---|---|---|---|---|
| REQ-BIN-001 | Smart-bin registry with location, capacity, type, status | bins | `services/bins.py` | `/bins` | `bins`, `bin_types` | `api/test_bins.py` | `architecture/domain-model.md` §4.1 | DESIGNED |
| REQ-BIN-002 | Device abstraction with sensor health and connectivity | bins | `services/sensors.py` | `/bins/{id}` | `bin_sensors` | `telemetry/test_sensor_health.py` | `architecture/domain-model.md` §4.4 | DESIGNED |
| REQ-BIN-003 | Telemetry ingestion with validation, dedup, latest-state | telemetry | `telemetry/ingest.py` | `/telemetry/ingest` | `bin_telemetry`, `bin_telemetry_latest`, `ingestion_batches` | `telemetry/test_ingestion_validation.py` | `architecture/domain-model.md` BR-02..05 | DESIGNED |
| REQ-BIN-004 | Threshold alerts, dedup, lifecycle | notifications | `services/alerts.py` | `/alerts` | `bin_alerts` | `telemetry/test_alerts.py` | `architecture/domain-model.md` §5.7 | DESIGNED |
| REQ-BIN-005 | Offline detection and sensor health monitoring | telemetry | `workers/jobs/detect_offline.py` | `/alerts` | `bin_sensors`, `bin_alerts` | `telemetry/test_offline_detection.py` | `architecture/domain-model.md` §4.4 | DESIGNED |
| REQ-BIN-006 | Explainable collection priority scoring | bin_intelligence | `analytics/scoring.py` | `/bins/priority` | `scoring_configurations` | `unit/test_priority_scoring.py` | `architecture/domain-model.md` §7.1 | DESIGNED |
| REQ-BIN-007 | Overflow-risk prediction with factor contribution | bin_intelligence | `analytics/risk.py` | `/bins/{id}/risk` | `ai_model_versions` | `ml/test_overflow_risk.py` | `architecture/domain-model.md` §7.2 | DESIGNED |
| REQ-IOT-001 | Device simulator (seeded, time-compressed, fault injection) | simulation | `app/simulation/*` | CLI | labelled rows | `simulation/test_simulator.py` | `iot/simulator.md` | DESIGNED |
| REQ-IOT-002 | Simulated data clearly labelled, never presented as live | telemetry | `provenance` labels | all telemetry | `source` columns | `simulation/test_simulation_labelling.py` | `architecture/decisions.md` ADR-0013 | DESIGNED |
| REQ-COL-001 | Full collection lifecycle (PLANNED→COMPLETED + exceptions) | collections | `services/collections.py` | `/collections/tasks/*` | `collection_tasks`, `collection_events` | `services/test_collection_lifecycle.py` | `architecture/domain-model.md` §4.2 | DESIGNED |
| REQ-COL-002 | Recurring schedules materialised into tasks | collections | `services/schedules.py` | `/collections/schedules` | `collection_schedules` | `services/test_schedules.py` | `architecture/domain-model.md` §6.2 | DESIGNED |
| REQ-COL-003 | Task requires quantity or exception reason | collections | service + DB CHECK | `/collections/tasks/{id}/complete` | CHECK on FAILED | `services/test_completion_rules.py` | BR-07 | DESIGNED |
| REQ-FLT-001 | Vehicle registry, statuses, capacity enforcement | fleet | `services/vehicles.py` | `/vehicles` | `vehicles`, `vehicle_capacities` | `services/test_vehicle_capacity.py` | `architecture/domain-model.md` §4.3 | DESIGNED |
| REQ-FLT-002 | Vehicle telemetry (labelled when simulated) | fleet | `services/vehicle_telemetry.py` | `/vehicles/{id}/telemetry` | `vehicle_telemetry` | `fleet/test_vehicle_telemetry.py` | `architecture/domain-model.md` §6.7 | DESIGNED |
| REQ-DRV-001 | Driver workflow: assigned route, stops, completion, exceptions | workforce | `services/driver_ops.py` | `/drivers/me/*` | `drivers`, `driver_assignments` | `services/test_driver_workflow.py` | `architecture/domain-model.md` §4.2 | DESIGNED |
| REQ-DRV-002 | Driver sees minimum necessary, own-tenant data only | workforce | `.own` scopes | `/drivers/me/*` | — | `security/test_driver_scope.py` | `security/rbac.md` §4.1 | DESIGNED |
| REQ-RTE-001 | Real VRP optimization (capacity, time windows, priorities, multi-vehicle, depot) | routing | `optimization/solver.py` (OR-Tools) | `/routes/optimize` | `route_optimization_runs` | `optimization/test_solver_constraints.py` | `architecture/decisions.md` ADR-0007 | DESIGNED |
| REQ-RTE-002 | Optimization runs stored immutably with full inputs | routing | append-only run store | `/routes/optimization-runs` | `route_optimization_runs` | `optimization/test_run_history.py` | `architecture/domain-model.md` §6.14 | DESIGNED |
| REQ-RTE-003 | Route comparison vs previous/baseline/manual, estimated vs measured | routing | `analytics/route_comparison.py` | `/routes/{id}/compare` | `route_comparisons` | `optimization/test_comparison.py` | `architecture/domain-model.md` §6.16 | DESIGNED |
| REQ-RTE-004 | Unassigned stops reported with reasons; honesty about optimality | routing | solver result mapping | `/routes/optimization-runs/{id}/result` | `route_optimization_runs.is_optimal` | `optimization/test_unassigned_stops.py` | `architecture/decisions.md` ADR-0007 | DESIGNED |
| REQ-FAC-001 | Facility registry with capabilities, hours, contact, utilization | facilities | `services/facilities.py` | `/facilities` | `facilities`, `facility_capabilities` | `services/test_facility_capability.py` | `architecture/domain-model.md` §7 | DESIGNED |
| REQ-FAC-002 | Capability enforcement on waste receipt | facilities | service rule + FK | `/waste-loads/{id}/receive` | `facility_capabilities` | `services/test_facility_capability.py` | BR-10 | DESIGNED |
| REQ-WST-001 | Structured waste taxonomy (11 categories + materials + tenant extensions) | assets | `services/taxonomy.py` | `/waste/categories` | `waste_categories`, `waste_materials` | `api/test_taxonomy.py` | `architecture/domain-model.md` §4 | DESIGNED |
| REQ-WST-002 | Waste loads with unique ID, origin, composition, destination, outcome | loads | `services/waste_loads.py` | `/waste-loads` | `waste_loads`, `waste_load_items` | `services/test_waste_loads.py` | `architecture/domain-model.md` §7.5 | DESIGNED |
| REQ-WST-003 | Traceability: "where did this waste go?" | loads | `services/traceability.py` | `/waste-loads/{id}/trace` | `waste_transfers`, processing tables | `services/test_traceability.py` | `architecture/domain-model.md` §19 | DESIGNED |

## 4. Intelligence, analytics and environment

| Req | Requirement | Subsystem | Impl | API | DB | Tests | Doc | Status |
|---|---|---|---|---|---|---|---|---|
| REQ-AI-001 | Waste image classification (upload→validate→preprocess→predict→confidence→top-k) | classification | `classification/pipeline.py` | `/waste/classify` | `waste_classifications` | `ml/test_classification_pipeline.py` | `ai/ai-architecture.md` §5 | DESIGNED |
| REQ-AI-002 | Pluggable backends permitting pretrained/custom/edge models | classification | `ClassificationBackend` protocol | — | `ai_model_versions` | `ml/test_backend_protocol.py` | `ai/ai-architecture.md` §5.1 | DESIGNED |
| REQ-AI-003 | Evaluation pipeline: accuracy/precision/recall/F1/confusion matrix | classification | `ml/evaluation/*` | `/models/{id}/versions/{v}/metrics` | `model_metrics` | `ml/test_metrics_computation.py` | `ai/model-cards.md` | DESIGNED |
| REQ-AI-004 | Low-confidence → human review; no hazardous auto-actions | classification | threshold gate | `/waste/classifications/{id}/review` | `needs_review` | `ml/test_low_confidence_routing.py` | BR-15 | DESIGNED |
| REQ-AI-005 | Human correction + feedback storage | classification | `services/classification_review.py` | review endpoint | `classification_feedback` | `ml/test_feedback_loop.py` | `ai/ai-architecture.md` §5.2 | DESIGNED |
| REQ-AI-006 | Forecasting with model version, horizon, uncertainty, input window | forecasting | `forecasting/*` | `/forecasts/*` | `forecast_runs`, `forecasts` | `ml/test_forecasting.py` | `ai/ai-architecture.md` §3 | DESIGNED |
| REQ-AI-007 | Forecasting baselines first; deep learning only if justified | forecasting | baseline always computed | `/forecasts/runs/{id}` | `forecasts.baseline_value` | `ml/test_baseline_comparison.py` | `ai/ai-architecture.md` §3 | DESIGNED |
| REQ-AI-008 | Anomaly detection with interpretable methods first | anomaly | `anomaly/detectors.py` | `/anomalies` | `anomalies` | `ml/test_anomaly.py` | `ai/ai-architecture.md` §4 | DESIGNED |
| REQ-AI-009 | Tool-bound assistant; never invents metrics | assistant | `assistant/tools.py`, `assistant/agent.py` | `/assistant/*` | conversations | `ai/test_grounding.py` | `ai/ai-architecture.md` §8 | DESIGNED |
| REQ-AI-010 | Assistant respects tenant + permissions; no destructive tools | assistant | registry permission binding | `/assistant/*` | — | `ai/test_tool_authorization.py`, `ai/test_tenant_leakage.py` | `ai/assistant-safety.md` | DESIGNED |
| REQ-AI-011 | Prompt-injection and exfiltration protection | assistant | data-slot confinement | `/assistant/*` | — | `ai/test_prompt_injection.py` | `ai/assistant-safety.md` | DESIGNED |
| REQ-AI-012 | Recommendation model with evidence, priority, lifecycle, feedback | recommendations | `recommendations/*` | `/recommendations` | `recommendations` | `ai/test_recommendation_integrity.py` | `architecture/domain-model.md` §4.5 | DESIGNED |
| REQ-AI-013 | Model registry with active/previous/experimental + rollback | ai_registry | `services/models.py` | `/models/*` | `ai_models`, `ai_model_versions` | `ml/test_model_registry.py` | `ai/model-registry.md` | DESIGNED |
| REQ-ANA-001 | Analytics APIs with date range, tenant, zone, category, facility, vehicle, route | analytics | `analytics/services/*` | `/analytics/*` | rollups | `analytics/test_aggregations.py` | `api/rest-api.md` §2.12 | DESIGNED |
| REQ-ANA-002 | Database-side aggregation; no full-table loads | analytics | repository aggregates | `/analytics/*` | indexes | `analytics/test_query_efficiency.py` | `architecture/architecture.md` §6 | DESIGNED |
| REQ-ANA-003 | Executive dashboard with KPIs, charts, map, alerts; no fake metrics | frontend | `features/dashboard/*` | `/analytics/executive-summary` | — | `e2e/dashboard.spec.ts` | `frontend/information-architecture.md` §4.1 | DESIGNED |
| REQ-ANA-004 | Operations dashboard (live bin status, queue, routes, drivers, incidents) | frontend | `features/operations/*` | several | read model | `e2e/operations.spec.ts` | `frontend/information-architecture.md` §4.2 | DESIGNED |
| REQ-ANA-005 | Map: bins, vehicles, facilities, zones, routes, hotspots | frontend | `components/map/*` | `/geo/nearby`, bbox filters | coordinate columns | `e2e/map.spec.ts` | `frontend/information-architecture.md` §5 | DESIGNED |
| REQ-ENV-001 | Recycling/recovery/composting/treatment/disposal tracking | recovery | `services/recovery.py` | `/recovery/*` | 4 processing tables | `services/test_recovery.py` | `architecture/domain-model.md` §7.8 | DESIGNED |
| REQ-ENV-002 | Diversion/recycling/landfill rates with explicit, configurable definitions | environment | `analytics/definitions.py` | `/analytics/environment` | `environmental_metrics.computation_definition_version` | `environment/test_metric_definitions.py` | `architecture/domain-model.md` §6 | DESIGNED |
| REQ-ENV-003 | Carbon estimates from versioned, sourced emission factors | environment | `environment/carbon.py` | `/analytics/environment` | `emission_factors`, `carbon_estimates` | `environment/test_carbon_estimation.py` | BR-11 | DESIGNED |
| REQ-ENV-004 | No fabricated environmental savings claims | all | provenance labels | all metrics | `provenance` columns | `tests/test_provenance_labels.py` | `architecture/decisions.md` ADR-0013 | DESIGNED |
| REQ-NOT-001 | Centralised notifications: 10 types, severity, dedup, preferences, channels | notifications | `services/notifications.py` | `/notifications` | `notifications`, `notification_preferences` | `services/test_notifications.py` | `architecture/domain-model.md` §9.1 | DESIGNED |
| REQ-RPT-001 | Report generation: 8 types with parameters, structured output, export | reporting | `reporting/*` | `/reports/*` | `report_definitions`, `report_runs` | `services/test_reports.py` | `architecture/domain-model.md` §9.4 | DESIGNED |
| REQ-INT-001 | Adapter interfaces with local development implementations | integrations | `integrations/*` | `/admin/integrations` | `integrations`, `webhooks` | `integrations/test_adapters.py` | `architecture/architecture.md` §7 | DESIGNED |
| REQ-INT-002 | CSV import with per-row validation and complete result reporting | integrations | `services/imports.py` | `/bins/import` etc. | — | `services/test_csv_import.py` | `architecture/architecture.md` | DESIGNED |

---

## 5. Coverage summary

| Category | Requirements tracked | Implemented | In progress | Designed |
|---|---|---|---|---|
| Platform/architecture | 13 | 0 | 0 | 13 |
| Identity/access/security | 14 | 0 | 0 | 14 |
| Waste/IoT/operations | 20 | 0 | 0 | 20 |
| Intelligence/analytics/environment | 22 | 0 | 0 | 22 |
| **Total** | **69** | **0** | **0** | **69** |

Every requirement in sections 0–80 of the master specification has a row here.
A requirement with no home would be an architecture gap, and there are none:
the two items deliberately outside scope (citizen mobile app, billing) are
recorded in `architecture/domain-model.md` §8 and `risks-and-assumptions.md` §5
with reasons, not silently dropped.

**Phase 0 conclusion:** traceability is complete at the design level; the matrix
becomes meaningful as `Status` advances at each phase gate.
