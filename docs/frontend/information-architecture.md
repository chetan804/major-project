# EcoMind-AI — Frontend Information Architecture

**Status:** Phase 0 baseline
**Stack:** React 18 + TypeScript + Vite + Tailwind + TanStack Query + React
Router + Recharts (charts) + Leaflet (maps)
**Related:** `../architecture/architecture.md`, `../security/rbac.md`, `../api/rest-api.md`

---

## 1. Design intent

The UI must read as an **operations console**, not a demo dashboard. Concrete
commitments:

1. **Information density over decoration.** Tables, dense KPI strips, and
   inline status are preferred to oversized hero cards. Max two accent colours.
2. **Every number is traceable.** Each KPI shows its provenance badge
   (Measured / Estimated / Predicted / Simulated) and links to the analytics
   endpoint that produced it.
3. **Status is never colour-only.** Every status uses a glyph/icon + text label
   in addition to colour (WCAG 1.4.1).
4. **No dead ends.** Every route resolves to a real page with loading, empty,
   error and permission-denied states — no placeholder pages, no buttons that
   do nothing (sections 18/19/62).
5. **Server state ≠ UI state ≠ auth state.** TanStack Query owns server data;
   a small Zustand store owns local UI state (filters, sidebar, density); auth
   state is separate and derived from `/auth/me`. No global store of API
   responses (section 52).
6. **String catalogues from day one.** User-facing copy lives in i18n resource
   files (`en-IN` first, `hi` scaffolded), never inline in deeply nested
   components (section 54).

---

## 2. Route map

```
/                                        → redirect to /dashboard or /login
/login                                   public
/register                                public (if self-signup enabled)
/forgot-password                         public
/reset-password?token=…                  public
/verify-email?token=…                    public

/dashboard                               Executive dashboard        analytics.read
/operations                              (redirect → /operations/live)
  /operations/live                       Live board                 analytics.read
  /operations/collection                 Collection tasks           collections.read
  /operations/collection/:taskId         Task detail + timeline     collections.read
  /operations/requests                   Collection requests        collections.read
  /operations/schedules                  Recurring schedules        collections.schedule.write
  /operations/routes                     Route list                 routes.read
  /operations/routes/:routeId            Route detail (stops, map)  routes.read
  /operations/routes/optimize            Optimization console       routes.optimize
  /operations/routes/optimization-runs   Run history + compare      routes.read
  /operations/routes/runs/:runId         Run detail / result apply  routes.read
  /operations/vehicles                   Fleet registry             vehicles.read
  /operations/vehicles/:vehicleId        Vehicle detail + telemetry vehicles.read
  /operations/drivers                    Driver registry            drivers.read
  /operations/drivers/:driverId          Driver detail + shifts     drivers.read

/waste
  /waste/bins                            Bin registry (table + map) bins.read
  /waste/bins/new                        Create bin                 bins.write
  /waste/bins/:binId                     Bin detail                 bins.read
    (tabs: state · telemetry · history · risk · maintenance)
  /waste/classification                  Classify images            classification.execute
  /waste/classification/review           Human verification queue   classification.review
  /waste/classification/history          Past classifications       classification.execute
  /waste/loads                           Waste load registry        loads.read
  /waste/loads/:loadId                   Load detail + trace        loads.read
  /waste/flow                            Source→facility flow view  loads.read
  /waste/taxonomy                        Categories & materials     taxonomy.write

/facilities
  /facilities                            Facility registry + map    facilities.read
  /facilities/:facilityId                Detail: capability, util   facilities.read
  /facilities/:facilityId/intake         Intake records             loads.read
  /facilities/:facilityId/processing     Processing outcomes        recovery.record

/analytics
  /analytics/waste                        Generation & composition   analytics.read
  /analytics/collection                   Performance                analytics.read
  /analytics/recycling                    Recovery & diversion       analytics.read
  /analytics/environment                  Carbon & environmental     analytics.read
  /analytics/forecasts                    Forecast explorer          forecasts.read
  /analytics/anomalies                    Anomaly explorer           anomalies.read
  /analytics/zones                        Zone comparison            analytics.read

/ai
  /ai/assistant                          Conversational console     assistant.use
  /ai/recommendations                    Recommendation inbox       recommendations.read
  /ai/models                             Model registry & metrics   models.read
  /ai/runs                               Job/run monitor (ML jobs)  models.read

/map                                     Unified operational map    bins.read

/reports
  /reports                               Report catalogue           reports.read
  /reports/runs                          Generated reports          reports.read
  /reports/runs/:runId                   Report viewer + export     reports.read

/admin
  /admin/users                           User management            users.read
  /admin/users/:userId                   User detail + roles        users.read
  /admin/roles                           Role & permission editor   roles.read
  /admin/settings                        Tenant settings            settings.read
  /admin/scoring                         Priority/risk weights      scoring.read
  /admin/integrations                    Integrations & webhooks    integrations.read
  /admin/audit                           Audit log                  audit.read
  /admin/alerts-config                   Alert thresholds           settings.write
  /admin/retention                       Data retention             retention.configure

/profile                                 Own profile               authenticated
/no-access                               Permission denied (403)     authenticated
/*                                       404 Not Found               public
```

Route metadata shape (single source for guard + nav + breadcrumb):

```ts
interface RouteMeta {
  path: string;
  element: React.LazyExoticComponent<React.ComponentType>;
  permission?: PermissionCode | PermissionCode[];  // absent ⇒ authenticated only
  nav?: { group: NavGroup; labelKey: string; icon: IconName; order: number };
  breadcrumb?: { labelKey: string; parent?: string };
  titleKey: string;
}
```

`nav` is rendered **only** when the user holds `permission` — so the sidebar
cannot offer a link the API will refuse. The guard is supplementary: the API
re-checks everything (section 11).

---

## 3. Navigation structure (permission-adaptive)

```
Dashboard                     analytics.read
Operations  ▸ Live board, Collection, Requests, Schedules,
              Routes, Optimization, Vehicles, Drivers
Waste       ▸ Bins, Classification, Review queue, Waste loads,
              Waste flow, Taxonomy
Facilities  ▸ Facilities, Intake, Processing
Analytics   ▸ Waste, Collection, Recycling, Environmental,
              Forecasts, Anomalies, Zones
AI          ▸ Assistant, Recommendations, Models, Runs
Map                           bins.read
Reports                       reports.read
Administration ▸ Users, Roles, Settings, Scoring, Integrations,
                 Audit logs, Retention         (each item permission-gated)
```

Role-shaped views (what each role actually sees, used as the E2E acceptance
list): `DRIVER` sees only **My Route / My Stops** (a distinct compact layout,
not the full console); `FACILITY_MANAGER` sees Facilities + Loads + Recovery;
`ANALYST` sees Analytics + Reports + Models (read-only) with no fleet mutation
actions; `VIEWER` sees dashboards without export buttons; `TENANT_ADMIN` sees
everything including Administration.

---

## 4. Page composition (key screens)

### 4.1 Executive dashboard `/dashboard`
* **KPI strip:** waste collected, diversion rate (with definition tooltip),
  collection efficiency, overflow incidents, active vehicles, completed
  collections, estimated CO₂e. Each KPI: value, delta vs previous period,
  provenance badge, "view source" link.
* **Charts:** generation trend (line, period toggle), composition (stacked bar
  or donut with measured/estimated split), collection performance
  (planned vs completed), recycling trend, zone comparison (bar), forecast
  overlay (dashed prediction + uncertainty band), route efficiency.
* **Map panel:** bins by fill state, overflow-risk highlights, vehicles,
  facilities, today's routes toggleable as layers.
* **Alerts rail:** critical / warning / info with acknowledge actions.
* Deliberate: a KPI with insufficient data renders `—` plus "insufficient data
  (n of m bins instrumented)" — never `0` (BR-17).

### 4.2 Live operations `/operations/live`
Auto-refreshing (30 s, pausable) board of: bin fill distribution, collection
queue with priority and factor breakdown, route status chips, driver status,
overdue/missed tasks, overflow-risk list, sensor-failure list, active incidents.
Filters: zone, status, severity, category, vehicle. Each row drills into the
owning detail page.

### 4.3 Optimization console `/operations/routes/optimize`
Three-step wizard: **select scope** (date, zones, vehicles) → **constraints and
objective weights** (with explanatory copy and "restore defaults") →
**review & run**. Shows the run as an async job with progress, then a
before/after comparison table (distance, duration, utilization, priority
coverage, estimated fuel and CO₂e, each labelled *estimated*) and a map with
baseline vs optimized routes. `Apply` is an explicit, confirmation-gated action
that creates DRAFT routes; a banner states that nothing is dispatched
automatically.

### 4.4 Bin detail `/waste/bins/:binId`
Header with code, category, status, fill gauge (with staleness indicator if
telemetry is old), location map. Tabs: **Telemetry** (chart + cursor-paginated
table), **History** (collections, alerts, maintenance timeline), **Risk**
(probability + contributing factors ranked — explainability from §7.2 of the
domain model), **Maintenance**. A visible warning banner appears when a bin has
no sensor, so an empty telemetry chart is never mistaken for "empty bin".

### 4.5 AI assistant `/ai/assistant`
Chat with a persistent right-hand **evidence panel**: for the selected answer,
the tool calls made, the metrics and source row ids, the model/version, and
limitations. Statements are colour-and-icon labelled by type (Database fact /
Prediction / Estimate / Recommendation / Unknown). A footer states which provider
is active; when the deterministic local provider is used the UI says so
explicitly. Suggested prompts are generated from the user's permissions (a
`FACILITY_MANAGER` is not offered fleet questions).

### 4.6 Waste load trace `/waste/loads/:loadId`
Horizontal chain-of-custody timeline: origin (collection event, bin, zone) →
vehicle/driver → transfers → destination facility → processing outcomes with
percentages and weights, and the resulting diversion/CO₂e contribution with
provenance labels. This page is the direct answer to "where did this waste go?".

---

## 5. Reusable component system

Built once, used everywhere (section 5 of the master prompt — no duplicate
implementations):

| Component | Purpose |
|---|---|
| `AppShell` / `Sidebar` / `Topbar` | Layout, tenant switcher, notifications bell, user menu, global search |
| `DataTable` | Column config, server-side pagination/sort/filter, row selection, column visibility, density, CSV export when permitted, skeleton rows, typed empty/error states |
| `KpiCard` | Value + delta + trend sparkline + **provenance badge** + source link |
| `StatusBadge` | Icon + label + colour from a central status map (never colour alone) |
| `ProvenanceBadge` | Measured / Estimated / Predicted / Simulated / User-entered |
| `Filters` | Typed filter bar driven by a declarative field spec; syncs to URL query params |
| `MapView` | Leaflet wrapper: layer toggles, clustered markers, viewport-bbox loading, legend, accessible list fallback for screen readers |
| `TimeSeriesChart`, `BarChart`, `DonutChart` | Thin Recharts wrappers with consistent axes, tooltips, uncertainty bands, empty state |
| `ConfirmDialog` | Required for destructive/dangerous actions; typed confirmation for `is_dangerous` permissions |
| `DrawerForm` | Create/edit in context without losing table state |
| `AsyncBoundary` | Loading (skeleton) / empty (with guidance) / error (with retry + request id) / permission-denied, in one place |
| `JobProgress` | Polls a job/run resource, shows steps, handles failure and retry |
| `AuditTrail` | Renders audit rows for a resource |
| `PermissionGate` | Declarative visibility control by permission (UX only) |

---

## 6. State, data and error handling

* **Server state:** TanStack Query with per-domain query-key factories,
  `staleTime` tuned per data class (live board 10 s, registries 60 s,
  analytics 5 min, configuration 30 min), and explicit invalidation on mutation.
* **Auth state:** `AuthProvider` holding the session, user, memberships and the
  effective permission set from `/auth/me`; a `RequirePermission` guard plus an
  axios/fetch interceptor that performs a **single** silent refresh on 401 and
  otherwise redirects to login preserving the intended path.
* **UI state:** Zustand slices for sidebar collapse, table density, saved
  filters, map layers — never mirrored server data.
* **Errors:** one `AsyncBoundary` renders the standard error envelope, showing
  `error.code`, the friendly message and the `request_id` (so a user can quote
  it to support). `INSUFFICIENT_DATA` renders as an informative state, not an
  error. `403` renders `/no-access` with the missing permission named.
* **Optimistic updates** only for low-risk toggles (alert acknowledge,
  notification read); every operational mutation awaits the server.
* **Accessibility:** skip-to-content link, semantic landmarks, focus-visible
  rings, keyboard-navigable tables and dialogs, ARIA live regions for job
  completion and toast notifications, contrast-checked palette, reduced-motion
  support, and charts accompanied by accessible data tables.
* **Responsive:** the console targets ≥1280 px with graceful degradation to
  768 px (collapsed sidebar, horizontally scrollable tables with sticky first
  column) and a compact card layout below 640 px for the driver view.

---

## 7. Frontend testing plan

| Layer | Tool | Coverage targets |
|---|---|---|
| Unit | Vitest | formatters, permission helpers, scoring explanation rendering, metric label mapping, date/timezone conversion |
| Component | React Testing Library | `DataTable` states, `KpiCard` provenance, `StatusBadge` non-colour indicator, `AsyncBoundary` branches, `ConfirmDialog` keyboard flow |
| Integration | MSW + RTL | feature flows with mocked API: bin create validation, task completion, optimization wizard, assistant evidence panel |
| E2E | Playwright | login → dashboard → create bin → view telemetry → create task → optimize → apply → dispatch → complete → analytics → report → assistant; plus RBAC denials per role and a simulated-flag visibility check |
| Accessibility | axe-core in component tests | no critical violations on the primary screens |

The E2E RBAC suite logs in as each seeded role and asserts that forbidden
navigation items are absent **and** that a direct URL visit renders
`/no-access` — supplementing, not replacing, the backend authorization suite.
