"""
Baseline reference data: the platform-wide seed content.

Everything in this module is **reference data with a stated provenance**, not
business results. Nothing here is a waste quantity, a KPI or a performance
figure: those are produced by the running system from the database.

Emission factors deserve a specific note. Every value carries a ``source`` and a
``methodology`` because an emission number without a citation is not a
measurement (BR-11). The values are transcribed from the cited public sources; a
tenant may supersede any of them through ``emission_factors.write``, which
requires the same fields. No emission figure in this codebase is an unexplained
constant.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal

__all__ = [
    "AI_MODELS",
    "BASELINE_BIN_TYPES",
    "BASELINE_FACILITY_TYPES",
    "BASELINE_VEHICLE_TYPES",
    "EMISSION_FACTORS",
    "INTEGRATIONS",
    "NOTIFICATION_TEMPLATES",
    "REPORT_DEFINITIONS",
    "RETENTION_POLICIES",
    "WASTE_CATEGORIES",
    "WASTE_MATERIALS",
]

# ---------------------------------------------------------------------------
# Waste taxonomy (erd.md §4)
# ---------------------------------------------------------------------------
#: The eleven baseline categories, shared by every tenant so that diversion and
#: carbon analytics stay comparable between municipalities.
WASTE_CATEGORIES: tuple[dict[str, object], ...] = (
    {
        "code": "MIXED_MSW",
        "name": "Mixed municipal solid waste",
        "description": "Unsegregated household and street waste.",
        "is_recyclable": False,
        "is_hazardous": False,
        "is_organic": False,
        "is_compostable": False,
        "disposal_route": "LANDFILL",
        "sensitivity_weight": Decimal("0.500"),
        "icon": "trash",
        "colour": "slate",
    },
    {
        "code": "ORGANIC_FOOD",
        "name": "Food and kitchen waste",
        "description": "Putrescible organic waste from households and food service.",
        "is_recyclable": False,
        "is_hazardous": False,
        "is_organic": True,
        "is_compostable": True,
        "disposal_route": "COMPOST",
        "sensitivity_weight": Decimal("0.900"),
        "icon": "leaf",
        "colour": "green",
    },
    {
        "code": "GARDEN_GREEN",
        "name": "Garden and green waste",
        "description": "Tree and garden trimmings, grass, dried leaves.",
        "is_recyclable": False,
        "is_hazardous": False,
        "is_organic": True,
        "is_compostable": True,
        "disposal_route": "COMPOST",
        "sensitivity_weight": Decimal("0.400"),
        "icon": "tree",
        "colour": "emerald",
    },
    {
        "code": "PAPER_CARDBOARD",
        "name": "Paper and cardboard",
        "description": "Corrugated cardboard, office paper, newsprint.",
        "is_recyclable": True,
        "is_hazardous": False,
        "is_organic": True,
        "is_compostable": False,
        "disposal_route": "RECYCLE",
        "sensitivity_weight": Decimal("0.300"),
        "icon": "package",
        "colour": "amber",
    },
    {
        "code": "PLASTIC",
        "name": "Plastics",
        "description": "Packaging and products made of thermoplastic polymers.",
        "is_recyclable": True,
        "is_hazardous": False,
        "is_organic": False,
        "is_compostable": False,
        "disposal_route": "RECYCLE",
        "sensitivity_weight": Decimal("0.700"),
        "icon": "bottle",
        "colour": "sky",
    },
    {
        "code": "GLASS",
        "name": "Glass",
        "description": "Container and flat glass.",
        "is_recyclable": True,
        "is_hazardous": False,
        "is_organic": False,
        "is_compostable": False,
        "disposal_route": "RECYCLE",
        "sensitivity_weight": Decimal("0.200"),
        "icon": "wine",
        "colour": "cyan",
    },
    {
        "code": "METAL",
        "name": "Metals",
        "description": "Ferrous and non-ferrous metals, including cans and foil.",
        "is_recyclable": True,
        "is_hazardous": False,
        "is_organic": False,
        "is_compostable": False,
        "disposal_route": "RECYCLE",
        "sensitivity_weight": Decimal("0.350"),
        "icon": "cog",
        "colour": "zinc",
    },
    {
        "code": "TEXTILES",
        "name": "Textiles",
        "description": "Clothing and household textiles.",
        "is_recyclable": True,
        "is_hazardous": False,
        "is_organic": False,
        "is_compostable": False,
        "disposal_route": "RECYCLE",
        "sensitivity_weight": Decimal("0.250"),
        "icon": "shirt",
        "colour": "violet",
    },
    {
        "code": "EWASTE",
        "name": "Electrical and electronic waste",
        "description": "Discarded electrical and electronic equipment.",
        "is_recyclable": True,
        "is_hazardous": True,
        "is_organic": False,
        "is_compostable": False,
        "disposal_route": "SPECIAL_HANDLING",
        "sensitivity_weight": Decimal("0.950"),
        "icon": "cpu",
        "colour": "rose",
    },
    {
        "code": "CONSTRUCTION_DEBRIS",
        "name": "Construction and demolition debris",
        "description": "Inert debris from construction, renovation and demolition.",
        "is_recyclable": False,
        "is_hazardous": False,
        "is_organic": False,
        "is_compostable": False,
        "disposal_route": "LANDFILL",
        "sensitivity_weight": Decimal("0.100"),
        "icon": "hammer",
        "colour": "stone",
    },
    {
        "code": "HAZARDOUS",
        "name": "Hazardous waste",
        "description": "Waste requiring special handling under regulation.",
        "is_recyclable": False,
        "is_hazardous": True,
        "is_organic": False,
        "is_compostable": False,
        "disposal_route": "SPECIAL_HANDLING",
        "sensitivity_weight": Decimal("1.000"),
        "icon": "alert-triangle",
        "colour": "red",
    },
)

#: Finer-grained materials under the baseline categories.
WASTE_MATERIALS: tuple[dict[str, object], ...] = (
    {"category": "PLASTIC", "code": "PET", "name": "PET (1)", "recyclability_grade": 5, "unit": "kg", "density_kg_per_l": Decimal("0.0014")},
    {"category": "PLASTIC", "code": "HDPE", "name": "HDPE (2)", "recyclability_grade": 5, "unit": "kg", "density_kg_per_l": Decimal("0.00095")},
    {"category": "PLASTIC", "code": "PVC", "name": "PVC (3)", "recyclability_grade": 2, "unit": "kg", "density_kg_per_l": Decimal("0.0014")},
    {"category": "PLASTIC", "code": "LDPE", "name": "LDPE (4)", "recyclability_grade": 4, "unit": "kg", "density_kg_per_l": Decimal("0.00092")},
    {"category": "PLASTIC", "code": "PP", "name": "PP (5)", "recyclability_grade": 4, "unit": "kg", "density_kg_per_l": Decimal("0.0009")},
    {"category": "PLASTIC", "code": "PS", "name": "PS (6)", "recyclability_grade": 2, "unit": "kg", "density_kg_per_l": Decimal("0.00105")},
    {"category": "PLASTIC", "code": "MIXED_PLASTIC", "name": "Mixed plastics", "recyclability_grade": 2, "unit": "kg", "density_kg_per_l": None},
    {"category": "PAPER_CARDBOARD", "code": "OCC", "name": "Old corrugated containers", "recyclability_grade": 5, "unit": "kg", "density_kg_per_l": None},
    {"category": "PAPER_CARDBOARD", "code": "OFFICE_PAPER", "name": "Office paper", "recyclability_grade": 5, "unit": "kg", "density_kg_per_l": None},
    {"category": "PAPER_CARDBOARD", "code": "NEWSPRINT", "name": "Newsprint", "recyclability_grade": 4, "unit": "kg", "density_kg_per_l": None},
    {"category": "GLASS", "code": "GLASS_CLEAR", "name": "Clear glass", "recyclability_grade": 5, "unit": "kg", "density_kg_per_l": None},
    {"category": "GLASS", "code": "GLASS_COLOURED", "name": "Coloured glass", "recyclability_grade": 4, "unit": "kg", "density_kg_per_l": None},
    {"category": "METAL", "code": "ALUMINIUM", "name": "Aluminium", "recyclability_grade": 5, "unit": "kg", "density_kg_per_l": None},
    {"category": "METAL", "code": "STEEL", "name": "Steel and tinplate", "recyclability_grade": 5, "unit": "kg", "density_kg_per_l": None},
    {"category": "METAL", "code": "COPPER", "name": "Copper", "recyclability_grade": 5, "unit": "kg", "density_kg_per_l": None},
    {"category": "TEXTILES", "code": "COTTON", "name": "Cotton textiles", "recyclability_grade": 3, "unit": "kg", "density_kg_per_l": None},
    {"category": "TEXTILES", "code": "POLYESTER", "name": "Polyester textiles", "recyclability_grade": 3, "unit": "kg", "density_kg_per_l": None},
    {"category": "ORGANIC_FOOD", "code": "FOOD_WASTE", "name": "Food waste", "recyclability_grade": 1, "unit": "kg", "density_kg_per_l": Decimal("0.0008")},
    {"category": "GARDEN_GREEN", "code": "GREEN_WASTE", "name": "Green waste", "recyclability_grade": 1, "unit": "kg", "density_kg_per_l": Decimal("0.0003")},
    {"category": "EWASTE", "code": "BATTERIES", "name": "Batteries", "recyclability_grade": 3, "unit": "kg", "density_kg_per_l": None},
    {"category": "EWASTE", "code": "CIRCUIT_BOARDS", "name": "Circuit boards", "recyclability_grade": 4, "unit": "kg", "density_kg_per_l": None},
    {"category": "CONSTRUCTION_DEBRIS", "code": "CONCRETE", "name": "Concrete and masonry", "recyclability_grade": 3, "unit": "kg", "density_kg_per_l": None},
    {"category": "CONSTRUCTION_DEBRIS", "code": "TIMBER", "name": "Timber", "recyclability_grade": 4, "unit": "kg", "density_kg_per_l": None},
)

# ---------------------------------------------------------------------------
# Emission factors (BR-11 — every value carries its source)
# ---------------------------------------------------------------------------
EMISSION_FACTORS: tuple[dict[str, object], ...] = (
    {
        "factor_code": "DIESEL_COMBUSTION_LITRE",
        "name": "Diesel combustion",
        "activity_type": "FUEL_COMBUSTION",
        "activity_unit": "litre",
        "factor_value": Decimal("2.68000000"),
        "result_unit": "KG_CO2E_PER_LITER",
        "source": "UK DEFRA / DESNZ Greenhouse Gas Conversion Factors, Fuels — Diesel (100% mineral diesel)",
        "source_url": "https://www.gov.uk/government/publications/greenhouse-gas-reporting-conversion-factors",
        "geography": "GLOBAL",
        "methodology": (
            "Complete combustion of one litre of mineral diesel, expressed as kg CO2 "
            "equivalent per litre including the CO2, CH4 and N2O components of the "
            "published factor."
        ),
        "effective_from": date(2023, 6, 1),
    },
    {
        "factor_code": "PETROL_COMBUSTION_LITRE",
        "name": "Petrol combustion",
        "activity_type": "FUEL_COMBUSTION",
        "activity_unit": "litre",
        "factor_value": Decimal("2.31000000"),
        "result_unit": "KG_CO2E_PER_LITER",
        "source": "UK DEFRA / DESNZ Greenhouse Gas Conversion Factors, Fuels — Petrol (100% mineral petrol)",
        "source_url": "https://www.gov.uk/government/publications/greenhouse-gas-reporting-conversion-factors",
        "geography": "GLOBAL",
        "methodology": "Complete combustion of one litre of mineral petrol, kg CO2e per litre.",
        "effective_from": date(2023, 6, 1),
    },
    {
        "factor_code": "CNG_COMBUSTION_KG",
        "name": "Compressed natural gas combustion",
        "activity_type": "FUEL_COMBUSTION",
        "activity_unit": "kg",
        "factor_value": Decimal("2.75000000"),
        "result_unit": "KG_CO2E_PER_KG",
        "source": "UK DEFRA / DESNZ Greenhouse Gas Conversion Factors, Fuels — Natural gas",
        "source_url": "https://www.gov.uk/government/publications/greenhouse-gas-reporting-conversion-factors",
        "geography": "GLOBAL",
        "methodology": "Combustion of one kilogram of natural gas, kg CO2e per kg.",
        "effective_from": date(2023, 6, 1),
    },
    {
        "factor_code": "GRID_ELECTRICITY_IN",
        "name": "Grid electricity, India",
        "activity_type": "ELECTRICITY",
        "activity_unit": "kWh",
        "factor_value": Decimal("0.71000000"),
        "result_unit": "KG_CO2E_PER_KWH",
        "source": "Central Electricity Authority (India), CO2 Baseline Database for the Indian Power Sector",
        "source_url": "https://cea.nic.in/",
        "geography": "IN",
        "methodology": (
            "Weighted average emission factor of the national grid, kg CO2 per kWh "
            "generated, as published in the annual baseline database."
        ),
        "effective_from": date(2023, 2, 1),
    },
    {
        "factor_code": "LANDFILL_MIXED_MSW",
        "name": "Mixed municipal waste to landfill",
        "activity_type": "WASTE_TREATMENT",
        "activity_unit": "kg",
        "factor_value": Decimal("0.45000000"),
        "result_unit": "KG_CO2E_PER_KG",
        "source": "UK DEFRA / DESNZ Greenhouse Gas Conversion Factors, Disposal — mixed commercial waste to landfill",
        "source_url": "https://www.gov.uk/government/publications/greenhouse-gas-reporting-conversion-factors",
        "geography": "GLOBAL",
        "methodology": (
            "Life-cycle emissions of disposing of one kilogram of mixed municipal "
            "waste in an engineered landfill, including transport and methane "
            "oxidation assumptions."
        ),
        "effective_from": date(2023, 6, 1),
    },
    {
        "factor_code": "LANDFILL_AVOIDED_RECYCLING",
        "name": "Avoided emissions from recycling (mixed dry recyclables)",
        "activity_type": "LANDFILL_AVOIDED",
        "activity_unit": "kg",
        "factor_value": Decimal("0.21000000"),
        "result_unit": "KG_CO2E_PER_KG",
        "source": "UK DEFRA / DESNZ Greenhouse Gas Conversion Factors, Recycling — mixed dry recyclables credit",
        "source_url": "https://www.gov.uk/government/publications/greenhouse-gas-reporting-conversion-factors",
        "geography": "GLOBAL",
        "methodology": (
            "Net avoided emissions per kilogram diverted from disposal to recycling, "
            "counting the displaced virgin material production."
        ),
        "effective_from": date(2023, 6, 1),
    },
    {
        "factor_code": "COMPOSTING_ORGANIC",
        "name": "Composting of organic waste",
        "activity_type": "COMPOSTING",
        "activity_unit": "kg",
        "factor_value": Decimal("0.08000000"),
        "result_unit": "KG_CO2E_PER_KG",
        "source": "UK DEFRA / DESNZ Greenhouse Gas Conversion Factors, Composting — open windrow",
        "source_url": "https://www.gov.uk/government/publications/greenhouse-gas-reporting-conversion-factors",
        "geography": "GLOBAL",
        "methodology": (
            "Emissions of composting one kilogram of organic waste in an open "
            "windrow, net of the soil-carbon benefit of the compost produced."
        ),
        "effective_from": date(2023, 6, 1),
    },
)

# ---------------------------------------------------------------------------
# Per-tenant baselines (cloned at provisioning)
# ---------------------------------------------------------------------------
BASELINE_BIN_TYPES: tuple[dict[str, object], ...] = (
    {"code": "BIN_120L", "name": "120 L wheeled bin", "capacity_liters": Decimal("120.000"), "material": "PLASTIC", "has_sensor_mount": True},
    {"code": "BIN_240L", "name": "240 L wheeled bin", "capacity_liters": Decimal("240.000"), "material": "PLASTIC", "has_sensor_mount": True},
    {"code": "BIN_660L", "name": "660 L wheeled bin", "capacity_liters": Decimal("660.000"), "material": "PLASTIC", "has_sensor_mount": True},
    {"code": "BIN_1100L", "name": "1100 L wheeled bin", "capacity_liters": Decimal("1100.000"), "material": "PLASTIC", "has_sensor_mount": True},
    {"code": "BIN_UNDERGROUND_3M3", "name": "Underground 3 m³", "capacity_liters": Decimal("3000.000"), "material": "STEEL", "has_sensor_mount": True},
    {"code": "SKIP_3M3", "name": "3 m³ skip container", "capacity_liters": Decimal("3000.000"), "material": "STEEL", "has_sensor_mount": False},
    {"code": "BIN_PUBLIC_50L", "name": "50 L public-facing bin", "capacity_liters": Decimal("50.000"), "material": "STEEL", "has_sensor_mount": False},
)

BASELINE_VEHICLE_TYPES: tuple[dict[str, object], ...] = (
    {"code": "TIPPER_7T", "name": "7 t tipper truck", "capacity_kg": Decimal("7000.000"), "capacity_m3": Decimal("12.000"), "axle_configuration": "4x2", "typical_crew_size": 2},
    {"code": "COMPACTOR_12T", "name": "12 t compactor", "capacity_kg": Decimal("12000.000"), "capacity_m3": Decimal("22.000"), "axle_configuration": "6x4", "typical_crew_size": 2},
    {"code": "COMPACTOR_16T", "name": "16 t compactor", "capacity_kg": Decimal("16000.000"), "capacity_m3": Decimal("28.000"), "axle_configuration": "8x4", "typical_crew_size": 3},
    {"code": "AUTORICKSHAW_LOADER", "name": "Auto-rickshaw loader", "capacity_kg": Decimal("750.000"), "capacity_m3": Decimal("2.500"), "axle_configuration": "3w", "typical_crew_size": 2},
    {"code": "BATTERY_EV_3T", "name": "3 t battery-electric loader", "capacity_kg": Decimal("3000.000"), "capacity_m3": Decimal("8.000"), "axle_configuration": "4x2", "typical_crew_size": 2},
    {"code": "TRACTOR_TRAILER", "name": "Tractor with trailer", "capacity_kg": Decimal("5000.000"), "capacity_m3": Decimal("10.000"), "axle_configuration": "tractor", "typical_crew_size": 2},
)

BASELINE_FACILITY_TYPES: tuple[dict[str, object], ...] = (
    {"code": "TRANSFER_STATION", "name": "Transfer station", "category": "TRANSFER_STATION"},
    {"code": "MRF", "name": "Material recovery facility", "category": "MATERIAL_RECOVERY"},
    {"code": "RECYCLING_CENTRE", "name": "Recycling centre", "category": "RECYCLING_CENTER"},
    {"code": "COMPOSTING_SITE", "name": "Composting site", "category": "COMPOSTING"},
    {"code": "TREATMENT_PLANT", "name": "Treatment plant", "category": "TREATMENT_PLANT"},
    {"code": "WTE_PLANT", "name": "Waste-to-energy plant", "category": "WASTE_TO_ENERGY"},
    {"code": "LANDFILL", "name": "Landfill", "category": "LANDFILL"},
)

# ---------------------------------------------------------------------------
# Model registry (erd.md §8.1–8.2)
# ---------------------------------------------------------------------------
#: Seeded as CANDIDATE. A version is only promoted to ACTIVE by an evaluation
#: run that records real metrics against a named dataset (ADR-0008), so the seed
#: deliberately does not claim any performance.
AI_MODELS: tuple[dict[str, object], ...] = (
    {
        "code": "WASTE_IMAGE_CLASSIFIER",
        "name": "Waste image classifier",
        "model_type": "WASTE_CLASSIFICATION",
        "task_description": (
            "Classify an uploaded photograph of waste into a canonical category, "
            "with a top-k ranking and a confidence score."
        ),
        "versions": (
            {
                "version": "1.0.0",
                "algorithm_family": "CLASSICAL_CV",
                "framework": "opencv + numpy",
                "hyperparameters": {
                    "resize_px": 224,
                    "colour_bins": 8,
                    "texture_grid": 4,
                    "top_k": 3,
                },
                "feature_definition": {
                    "features": [
                        "mean_rgb",
                        "std_rgb",
                        "colour_histogram_8x8x8_normalised",
                        "edge_density",
                        "specular_fraction",
                        "aspect_ratio",
                    ],
                    "order": [
                        "mean_rgb",
                        "std_rgb",
                        "colour_histogram_8x8x8_normalised",
                        "edge_density",
                        "specular_fraction",
                        "aspect_ratio",
                    ],
                },
                "notes": (
                    "Classical computer-vision backend. Evaluated on a documented "
                    "synthetic corpus before promotion; the evaluation type is "
                    "recorded with every metric."
                ),
            },
        ),
    },
    {
        "code": "BIN_FILL_FORECAST",
        "name": "Bin fill forecast",
        "model_type": "FILL_FORECAST",
        "task_description": (
            "Forecast the fill percentage of a bin over a horizon, with an "
            "uncertainty interval derived from backtest residuals."
        ),
        "versions": (
            {
                "version": "1.0.0",
                "algorithm_family": "SEASONAL_NAIVE",
                "framework": "python + numpy",
                "hyperparameters": {
                    "season_length_days": 7,
                    "damped_trend": 0.5,
                    "residual_quantiles": [0.1, 0.9],
                },
                "feature_definition": {
                    "features": ["fill_percentage_history", "hour_of_day", "day_of_week"],
                    "order": ["fill_percentage_history", "hour_of_day", "day_of_week"],
                },
                "notes": (
                    "Seasonal-naive baseline with a damped trend. Deliberately the "
                    "first ACTIVE model: it is defensible and its uncertainty is "
                    "derived from measured backtest residuals rather than assumed."
                ),
            },
        ),
    },
    {
        "code": "WASTE_VOLUME_FORECAST",
        "name": "Waste volume forecast",
        "model_type": "VOLUME_FORECAST",
        "task_description": "Forecast the collected waste volume for a zone or the tenant.",
        "versions": (
            {
                "version": "1.0.0",
                "algorithm_family": "EXPONENTIAL_SMOOTHING",
                "framework": "python + numpy",
                "hyperparameters": {"alpha": 0.3, "beta": 0.1, "season_length_days": 7},
                "feature_definition": {
                    "features": ["daily_collected_kg_history", "day_of_week"],
                    "order": ["daily_collected_kg_history", "day_of_week"],
                },
            },
        ),
    },
    {
        "code": "TELEMETRY_ANOMALY_DETECTOR",
        "name": "Telemetry anomaly detector",
        "model_type": "ANOMALY_DETECTION",
        "task_description": (
            "Flag telemetry readings that deviate from the bin's own recent "
            "behaviour, using interpretable univariate methods."
        ),
        "versions": (
            {
                "version": "1.0.0",
                "algorithm_family": "ZSCORE",
                "framework": "python + numpy",
                "hyperparameters": {"window": 48, "z_threshold": 3.0, "min_samples": 12},
                "feature_definition": {
                    "features": ["fill_percentage", "battery_percentage", "temperature_c"],
                    "order": ["fill_percentage", "battery_percentage", "temperature_c"],
                },
                "notes": (
                    "Rolling z-score first, IQR fences as a cross-check. Isolation "
                    "Forest is only used where the univariate methods demonstrably "
                    "fall short (domain-model.md §7.3)."
                ),
            },
        ),
    },
)

# ---------------------------------------------------------------------------
# Reporting, notifications, integrations, retention
# ---------------------------------------------------------------------------
REPORT_DEFINITIONS: tuple[dict[str, object], ...] = (
    {
        "code": "COLLECTION_PERFORMANCE",
        "name": "Collection performance",
        "description": "Completion, missed and overdue collections by zone and date.",
        "report_type": "COLLECTION_PERFORMANCE",
        "data_provider": "app.reporting.providers.collection_performance",
        "parameter_schema": {
            "type": "object",
            "properties": {
                "from": {"type": "string", "format": "date"},
                "to": {"type": "string", "format": "date"},
                "zone_id": {"type": "string", "format": "uuid"},
                "granularity": {"type": "string", "enum": ["day", "week", "month"]},
            },
            "required": ["from", "to"],
            "additionalProperties": False,
        },
    },
    {
        "code": "WASTE_GENERATION",
        "name": "Waste generation",
        "description": "Collected quantity by waste category and zone.",
        "report_type": "WASTE_GENERATION",
        "data_provider": "app.reporting.providers.waste_generation",
        "parameter_schema": {
            "type": "object",
            "properties": {
                "from": {"type": "string", "format": "date"},
                "to": {"type": "string", "format": "date"},
                "zone_id": {"type": "string", "format": "uuid"},
                "waste_category_id": {"type": "string", "format": "uuid"},
            },
            "required": ["from", "to"],
            "additionalProperties": False,
        },
    },
    {
        "code": "ENVIRONMENTAL_SUMMARY",
        "name": "Environmental summary",
        "description": "Diversion, recovery, disposal and estimated carbon for a period.",
        "report_type": "ENVIRONMENTAL",
        "data_provider": "app.reporting.providers.environmental_summary",
        "parameter_schema": {
            "type": "object",
            "properties": {
                "from": {"type": "string", "format": "date"},
                "to": {"type": "string", "format": "date"},
                "zone_id": {"type": "string", "format": "uuid"},
            },
            "required": ["from", "to"],
            "additionalProperties": False,
        },
    },
    {
        "code": "FLEET_UTILISATION",
        "name": "Fleet utilisation",
        "description": "Dispatched routes, load against capacity and distance by vehicle.",
        "report_type": "VEHICLE",
        "data_provider": "app.reporting.providers.fleet_utilisation",
        "parameter_schema": {
            "type": "object",
            "properties": {
                "from": {"type": "string", "format": "date"},
                "to": {"type": "string", "format": "date"},
                "vehicle_id": {"type": "string", "format": "uuid"},
            },
            "required": ["from", "to"],
            "additionalProperties": False,
        },
    },
    {
        "code": "BIN_STATUS",
        "name": "Bin status register",
        "description": "Every bin with its current fill, sensor state and last collection.",
        "report_type": "OPERATIONAL",
        "data_provider": "app.reporting.providers.bin_status",
        "parameter_schema": {
            "type": "object",
            "properties": {
                "zone_id": {"type": "string", "format": "uuid"},
                "status": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
)

NOTIFICATION_TEMPLATES: tuple[dict[str, object], ...] = (
    {
        "notification_type": "BIN_OVERFLOW",
        "channel": "IN_APP",
        "subject_template": "Bin {{ bin_code }} has overflowed",
        "body_template": (
            "Bin {{ bin_code }} in {{ zone_name }} reported a fill level of "
            "{{ fill_percentage }}% at {{ triggered_at }}, above the "
            "{{ threshold_value }}% threshold."
        ),
        "variables": ["bin_code", "zone_name", "fill_percentage", "threshold_value", "triggered_at"],
    },
    {
        "notification_type": "OVERFLOW_RISK",
        "channel": "IN_APP",
        "subject_template": "Overflow risk for bin {{ bin_code }}",
        "body_template": (
            "Bin {{ bin_code }} is predicted to reach {{ predicted_fill }}% within "
            "{{ horizon_hours }} hours. Predicted value — not a measurement."
        ),
        "variables": ["bin_code", "predicted_fill", "horizon_hours"],
    },
    {
        "notification_type": "SENSOR_OFFLINE",
        "channel": "IN_APP",
        "subject_template": "Sensor {{ device_id }} is offline",
        "body_template": (
            "Sensor {{ device_id }} on bin {{ bin_code }} has not reported since "
            "{{ last_seen_at }}."
        ),
        "variables": ["device_id", "bin_code", "last_seen_at"],
    },
    {
        "notification_type": "LOW_BATTERY",
        "channel": "IN_APP",
        "subject_template": "Low battery on sensor {{ device_id }}",
        "body_template": "Sensor {{ device_id }} reports {{ battery_percentage }}% battery.",
        "variables": ["device_id", "battery_percentage"],
    },
    {
        "notification_type": "COLLECTION_OVERDUE",
        "channel": "IN_APP",
        "subject_template": "Collection {{ task_code }} is overdue",
        "body_template": (
            "Task {{ task_code }} for bin {{ bin_code }} was planned for "
            "{{ planned_date }} and is still not complete."
        ),
        "variables": ["task_code", "bin_code", "planned_date"],
    },
    {
        "notification_type": "COLLECTION_MISSED",
        "channel": "IN_APP",
        "subject_template": "Collection {{ task_code }} was missed",
        "body_template": "Task {{ task_code }} was not completed on {{ planned_date }}.",
        "variables": ["task_code", "planned_date"],
    },
    {
        "notification_type": "ANOMALY_DETECTED",
        "channel": "IN_APP",
        "subject_template": "Anomaly detected: {{ metric_name }}",
        "body_template": (
            "{{ subject_label }} reported {{ observed_value }} where "
            "{{ expected_value }} was expected ({{ detection_method }}, "
            "{{ deviation }} {{ deviation_unit }})."
        ),
        "variables": [
            "subject_label",
            "metric_name",
            "observed_value",
            "expected_value",
            "detection_method",
            "deviation",
            "deviation_unit",
        ],
    },
    {
        "notification_type": "REPORT_READY",
        "channel": "IN_APP",
        "subject_template": "Report {{ report_name }} is ready",
        "body_template": "Report {{ report_name }} finished with {{ row_count }} rows.",
        "variables": ["report_name", "row_count"],
    },
    {
        "notification_type": "SYSTEM",
        "channel": "IN_APP",
        "subject_template": "{{ title }}",
        "body_template": "{{ body }}",
        "variables": ["title", "body"],
    },
    {
        "notification_type": "ROUTE_DELAY",
        "channel": "IN_APP",
        "subject_template": "Route {{ route_code }} is behind schedule",
        "body_template": (
            "Route {{ route_code }} is {{ minutes_behind }} minutes behind its plan "
            "at {{ completed_stop_count }} of {{ stop_count }} stops."
        ),
        "variables": ["route_code", "minutes_behind", "completed_stop_count", "stop_count"],
    },
)

INTEGRATIONS: tuple[dict[str, object], ...] = (
    {
        "code": "LOCAL_HAVERSINE_ROUTING",
        "name": "Local haversine routing",
        "integration_type": "ROUTING",
        "adapter_class": "app.integrations.routing.HaversineRoutingProvider",
        "configuration": {"average_speed_kph": 24.0, "note": "deterministic local provider"},
        "is_enabled": True,
    },
    {
        "code": "CONSOLE_EMAIL",
        "name": "Console email",
        "integration_type": "EMAIL",
        "adapter_class": "app.integrations.notifications.ConsoleEmailProvider",
        "configuration": {"note": "development adapter; logs instead of sending"},
        "is_enabled": True,
    },
    {
        "code": "LOCAL_STORAGE",
        "name": "Local filesystem storage",
        "integration_type": "STORAGE",
        "adapter_class": "app.integrations.storage.LocalStorageProvider",
        "configuration": {"note": "development adapter"},
        "is_enabled": True,
    },
    {
        "code": "LOCAL_LLM",
        "name": "Local deterministic assistant",
        "integration_type": "LLM",
        "adapter_class": "app.assistant.providers.LocalDeterministicAssistant",
        "configuration": {"note": "deterministic, tool-bound; no external model call"},
        "is_enabled": True,
    },
    {
        "code": "LOCAL_SYNTHETIC_WEATHER",
        "name": "Synthetic weather",
        "integration_type": "WEATHER",
        "adapter_class": "app.integrations.weather.SyntheticWeatherProvider",
        "configuration": {"note": "seeded synthetic provider, labelled SIMULATED"},
        "is_enabled": True,
    },
)

RETENTION_POLICIES: tuple[dict[str, object], ...] = (
    {"data_class": "BIN_TELEMETRY", "retention_days": 730, "archive_before_delete": True, "description": "Raw bin telemetry readings."},
    {"data_class": "VEHICLE_TELEMETRY", "retention_days": 365, "archive_before_delete": True, "description": "Raw vehicle position samples."},
    {"data_class": "AUDIT_LOG", "retention_days": 730, "archive_before_delete": True, "description": "Compliance audit trail."},
    {"data_class": "NOTIFICATION", "retention_days": 180, "archive_before_delete": False, "description": "Delivered notifications."},
    {"data_class": "JOB_RUN", "retention_days": 90, "archive_before_delete": False, "description": "Background job execution records."},
    {"data_class": "ANOMALY", "retention_days": 730, "archive_before_delete": True, "description": "Detected anomalies."},
    {"data_class": "REPORT_RUN", "retention_days": 730, "archive_before_delete": True, "description": "Report runs and their payloads."},
)
