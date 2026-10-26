"""Source Verification Audit Pass and Calculator Auto-Router for Project eMyrge.

Implements:
- F-17: Source-Verification Audit Pass (Numerical claim extraction, discrepancy detection,
  and hallucination warning annotations).
- F-18: Calculator Prompt Auto-Hook & Safety-Critical Intent Classifier.

Designed for zero external dependencies (pure Python standard library).
Provides 100% backwards-compatibility with tests.conftest.SourceAuditOracle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Data Models and Result Types
# ---------------------------------------------------------------------------

class ClaimStatus(str, Enum):
    """Verification classification of a numerical assertion."""
    VERIFIED = "VERIFIED"
    DISCREPANCY = "DISCREPANCY"
    UNGROUNDED = "UNGROUNDED"


@dataclass
class FlaggedClaim:
    """Represents a contradicted or ungrounded claim detected in draft text."""
    claim: str
    status: str  # "DISCREPANCY" or "UNGROUNDED"
    warning: str
    source_values: List[str] = field(default_factory=list)
    start_char: Optional[int] = None
    end_char: Optional[int] = None
    numeric_value: Optional[float] = None
    unit: Optional[str] = None

    def __getitem__(self, item: str) -> Any:
        """Enables dictionary subscripting for compatibility with test suites."""
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim": self.claim,
            "status": self.status,
            "warning": self.warning,
            "source_values": self.source_values,
            "start_char": self.start_char,
            "end_char": self.end_char,
            "numeric_value": self.numeric_value,
            "unit": self.unit,
        }


@dataclass
class AuditReport:
    """Report returned by SourceAudit.audit()."""
    is_clean: bool
    flagged_claims: List[FlaggedClaim]
    annotated_text: str

    @property
    def is_grounded(self) -> bool:
        return not any(f.status == ClaimStatus.DISCREPANCY.value for f in self.flagged_claims)

    def __getitem__(self, item: str) -> Any:
        """Enables dictionary subscripting (e.g. audit['is_clean'])."""
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_clean": self.is_clean,
            "flagged_claims": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.flagged_claims],
            "annotated_text": self.annotated_text,
        }


class CalculatorType(str, Enum):
    """Supported deterministic survival calculator domains."""
    WATER = "water"
    SOLAR = "solar"
    MEDICAL = "medical"
    ELECTRICAL = "electrical"
    GENERAL = "general"


@dataclass
class CalculatorRouteResult:
    """Detailed intent analysis and extracted parameters for calculator routing."""
    route: str
    calculator_type: CalculatorType
    confidence: float
    matched_keywords: List[str]
    extracted_parameters: Dict[str, Any] = field(default_factory=dict)
    suggested_ui_widget: Optional[str] = None

    def __getitem__(self, item: str) -> Any:
        if item == "type":
            return self.route
        if item in ("params", "extracted_parameters"):
            return self.extracted_parameters
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "route": self.route,
            "calculator_type": self.calculator_type.value,
            "confidence": self.confidence,
            "matched_keywords": self.matched_keywords,
            "extracted_parameters": self.extracted_parameters,
            "suggested_ui_widget": self.suggested_ui_widget,
        }


# ---------------------------------------------------------------------------
# Source Verification Audit Engine (F-17)
# ---------------------------------------------------------------------------

class SourceAudit:
    """Audits draft answers against retrieved offline source passages for numerical accuracy.
    
    Extracts numerical claims with physical/medical units, cross-references them against
    retrieved passages, and flags discrepancies or unverified assertions.
    """

    # Canonical regex matching SourceAuditOracle in tests/conftest.py
    NUMBER_PATTERN = re.compile(
        r"(?<![\w.])(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\s*(mg|ml|drops|liters?|gallons?|ppm|volts?|amps?|watts?|ohms?|%|ah|hours?|minutes?|seconds?|µg|μg|mcg|Ω)",
        re.IGNORECASE,
    )

    # Unit normalization mapping to handle pluralization and abbreviations
    UNIT_ALIASES = {
        "l": "liters",
        "liter": "liters",
        "liters": "liters",
        "drop": "drops",
        "drops": "drops",
        "gal": "gallons",
        "gallon": "gallons",
        "gallons": "gallons",
        "volt": "volts",
        "volts": "volts",
        "amp": "amps",
        "amps": "amps",
        "watt": "watts",
        "watts": "watts",
        "ohm": "ohms",
        "ohms": "ohms",
        "Ω": "ohms",
        "µg": "µg",
        "μg": "µg",
        "mcg": "µg",
        "hour": "hours",
        "hours": "hours",
        "minute": "minutes",
        "minutes": "minutes",
        "second": "seconds",
        "seconds": "seconds",
    }

    @classmethod
    def _unit_regex(cls, unit: str) -> str:
        u = unit.lower()
        if u in ("minute", "minutes"):
            return r"minutes?"
        elif u in ("hour", "hours"):
            return r"hours?"
        elif u in ("second", "seconds"):
            return r"seconds?"
        elif u in ("drop", "drops"):
            return r"drops?"
        elif u in ("liter", "liters", "litre", "litres"):
            return r"lit(?:er|re)s?"
        elif u in ("gallon", "gallons"):
            return r"gallons?"
        elif u in ("volt", "volts"):
            return r"volts?"
        elif u in ("amp", "amps", "ampere", "amperes"):
            return r"amp(?:ere)?s?"
        elif u in ("watt", "watts"):
            return r"watts?"
        elif u in ("ohm", "ohms", "Ω", "ω", "\u03a9", "\u2126", "\u03c9"):
            return r"(?:ohms?|[Ω\u03a9\u2126])"
        elif u in ("µg", "μg", "mcg", "\u00b5g", "\u03bcg"):
            return r"(?:µg|μg|mcg)"
        else:
            return re.escape(unit)

    @classmethod
    def audit(
        cls,
        draft_text: str,
        source_passages: List[str],
        allow_numeric_equivalence: bool = True,
    ) -> AuditReport:
        """Audits a draft text against a list of offline source passages.

        Args:
            draft_text: LLM generated answer or field note draft.
            source_passages: Retrieved article or lesson text segments.
            allow_numeric_equivalence: If True, treats mathematically identical numbers
                (e.g., 150.0 mg vs 150 mg) as matching.

        Returns:
            AuditReport containing is_clean status, list of FlaggedClaim objects,
            and annotated_text with appended warning notes.
        """
        if not draft_text:
            return AuditReport(is_clean=True, flagged_claims=[], annotated_text="")

        if source_passages is None:
            source_passages = []

        combined_sources = " ".join(source_passages).lower()

        # Extract claims with positions
        flagged: List[FlaggedClaim] = []

        for match in cls.NUMBER_PATTERN.finditer(draft_text):
            val_str, unit = match.groups()
            val = float(val_str)
            start_pos, end_pos = match.span()

            # Pattern 1: Exact string search as in SourceAuditOracle
            u_pat = cls._unit_regex(unit)
            exact_pattern = re.compile(rf"(?<![\d.]){re.escape(val_str)}\s*{u_pat}(?![\w])", re.IGNORECASE)
            exact_match_found = bool(exact_pattern.search(combined_sources))

            # Pattern 2: Search if unit exists in sources with any number
            comp_pattern = re.compile(rf"(?<![\d.])(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\s*{u_pat}(?![\w])", re.IGNORECASE)
            source_matches = comp_pattern.findall(combined_sources)

            # Check mathematical/float equivalence if enabled
            float_match_found = False
            if allow_numeric_equivalence and source_matches:
                for s_val in source_matches:
                    try:
                        if abs(float(s_val) - val) < 1e-9:
                            float_match_found = True
                            break
                    except ValueError:
                        continue

            if exact_match_found or float_match_found:
                # Verified against source passage
                continue

            # If not verified, determine whether it is a DISCREPANCY or UNGROUNDED
            if source_matches:
                flagged.append(
                    FlaggedClaim(
                        claim=f"{val_str} {unit}",
                        status=ClaimStatus.DISCREPANCY.value,
                        source_values=[f"{s} {unit}" for s in source_matches],
                        warning=f"[WARNING: Discrepancy detected: Draft states {val_str} {unit}, but source states {source_matches[0]} {unit}]",
                        start_char=start_pos,
                        end_char=end_pos,
                        numeric_value=val,
                        unit=unit,
                    )
                )
            else:
                flagged.append(
                    FlaggedClaim(
                        claim=f"{val_str} {unit}",
                        status=ClaimStatus.UNGROUNDED.value,
                        source_values=[],
                        warning=f"[NOTE: Unverified assertion: {val_str} {unit} not found in offline references]",
                        start_char=start_pos,
                        end_char=end_pos,
                        numeric_value=val,
                        unit=unit,
                    )
                )

        is_clean = len(flagged) == 0
        annotated_text = draft_text
        for item in flagged:
            annotated_text += f"\n{item.warning}"

        return AuditReport(
            is_clean=is_clean,
            flagged_claims=flagged,
            annotated_text=annotated_text,
        )

    @classmethod
    def audit_response(cls, response_text: str, context_sources: List[str]) -> AuditReport:
        """Alias conforming strictly to PROJECT.md line 176 contract."""
        return cls.audit(response_text, context_sources)


# ---------------------------------------------------------------------------
# Safety-Critical Calculator Auto-Router (F-18)
# ---------------------------------------------------------------------------

class CalculatorRouter:
    """Routes incoming queries to deterministic survival calculators based on safety intent.
    
    Identifies queries requiring mathematical dosing, electrical calculation,
    or solar load sizing, extracts basic parameters, and triggers pre-calculation.
    """

    # Keyword patterns mapped strictly to test_tier1_features.py requirements
    WATER_PATTERN = re.compile(
        r"\b(bleach|iodine|purif(?:y|ication)|chlorin(?:e|ate)?|turbid(?:ity)?|cloudy|water|boil(?:ing)?|sodis|disinfect(?:ion)?)\b",
        re.IGNORECASE,
    )
    SOLAR_PATTERN = re.compile(
        r"\b(solar(?:-powered|\s+panel|\s+array)?|battery|wh|watt-hours?|pv\s+array|inverter|depth\s+of\s+discharge|autonomy\s+days?|amp-hours?|ah)\b",
        re.IGNORECASE,
    )
    MEDICAL_PATTERN = re.compile(
        r"\b(dos(?:e|age|ing)|ibuprofen|paracetamol|acetaminophen|ors|oral\s+rehydration|dehydration|pediatric|mg/kg)\b",
        re.IGNORECASE,
    )
    ELECTRICAL_PATTERN = re.compile(
        r"\b(voltage|wire|wire\s+gauge|conductor|ohm|ohms?|ohms?\s+law|amps?|amperes?|resistance|voltage\s+drop|dc\s+circuit)\b",
        re.IGNORECASE,
    )

    @classmethod
    def classify_query(cls, query: str) -> str:
        """Classifies query intent into a calculator route string.

        Conforms strictly to test_calculator_prompt_auto_hook_f18:
        Priority sequence: water -> solar -> medical -> electrical -> general.

        Args:
            query: User prompt or radio message text.

        Returns:
            One of: "water", "solar", "medical", "electrical", "general".
        """
        if not query:
            return "general"

        q_lower = query.lower()

        # Follow evaluation sequence matching test_tier1_features.py line 363-372
        if cls.WATER_PATTERN.search(q_lower):
            return "water"
        elif cls.SOLAR_PATTERN.search(q_lower):
            return "solar"
        elif cls.MEDICAL_PATTERN.search(q_lower):
            return "medical"
        elif cls.ELECTRICAL_PATTERN.search(q_lower):
            return "electrical"
        else:
            return "general"

    @classmethod
    def route(cls, query: str) -> str:
        """Alias for classify_query."""
        return cls.classify_query(query)

    @classmethod
    def analyze_query(cls, query: str) -> CalculatorRouteResult:
        """Performs deep query analysis with parameter extraction and UI widget metadata."""
        route_str = cls.classify_query(query)
        calc_type = CalculatorType(route_str)

        matched_keywords: List[str] = []
        extracted_params: Dict[str, Any] = {}

        if not query:
            return CalculatorRouteResult(
                route="general",
                calculator_type=CalculatorType.GENERAL,
                confidence=0.0,
                matched_keywords=[],
                extracted_parameters={},
                suggested_ui_widget=None,
            )

        q_lower = query.lower()

        if calc_type == CalculatorType.WATER:
            matched_keywords = cls.WATER_PATTERN.findall(q_lower)
            extracted_params = cls._extract_water_parameters(q_lower)
            ui_widget = "water-purification-panel"
        elif calc_type == CalculatorType.SOLAR:
            matched_keywords = cls.SOLAR_PATTERN.findall(q_lower)
            extracted_params = cls._extract_solar_parameters(q_lower)
            ui_widget = "solar-battery-panel"
        elif calc_type == CalculatorType.MEDICAL:
            matched_keywords = cls.MEDICAL_PATTERN.findall(q_lower)
            extracted_params = cls._extract_medical_parameters(q_lower)
            ui_widget = "medical-rehydration-panel"
        elif calc_type == CalculatorType.ELECTRICAL:
            matched_keywords = cls.ELECTRICAL_PATTERN.findall(q_lower)
            extracted_params = cls._extract_electrical_parameters(q_lower)
            ui_widget = "electrical-formulas-panel"
        else:
            ui_widget = None

        confidence = min(1.0, 0.4 + (0.2 * len(matched_keywords))) if matched_keywords else 0.0

        return CalculatorRouteResult(
            route=route_str,
            calculator_type=calc_type,
            confidence=round(confidence, 2),
            matched_keywords=list(set(matched_keywords)),
            extracted_parameters=extracted_params,
            suggested_ui_widget=ui_widget,
        )

    @classmethod
    def _extract_water_parameters(cls, text: str) -> Dict[str, Any]:
        """Extracts volume, turbidity, and chemical method from water query."""
        params: Dict[str, Any] = {}

        # Volume extraction (liters or gallons)
        vol_match = re.search(r"(\d+(?:\.\d+)?)\s*(liters?|litres?|l|gallons?|gal)", text, re.IGNORECASE)
        if vol_match:
            val = float(vol_match.group(1))
            unit = vol_match.group(2).lower()
            if "gal" in unit:
                params["volume_gallons"] = val
                params["volume_liters"] = round(val * 3.78541, 2)
            else:
                params["volume_liters"] = val

        # Turbidity
        if re.search(r"\b(turbid|cloudy|muddy|dirty|pond|stream|river)\b", text, re.IGNORECASE):
            params["is_turbid"] = True
        elif re.search(r"\b(clear|tap|clean|filtered)\b", text, re.IGNORECASE):
            params["is_turbid"] = False

        # Method
        if "iodine" in text:
            params["method"] = "iodine"
        elif "bleach" in text:
            params["method"] = "bleach"
        elif "boil" in text:
            params["method"] = "boiling"
        elif "sodis" in text:
            params["method"] = "sodis"

        return params

    @classmethod
    def _extract_solar_parameters(cls, text: str) -> Dict[str, Any]:
        """Extracts daily Wh, voltage, and autonomy days from solar query."""
        params: Dict[str, Any] = {}

        wh_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:wh|watt-hours?|watts?-hours?)", text, re.IGNORECASE)
        if wh_match:
            params["daily_wh"] = float(wh_match.group(1))

        volt_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:v|volts?)", text, re.IGNORECASE)
        if volt_match:
            params["system_voltage"] = float(volt_match.group(1))

        days_match = re.search(r"(\d+(?:\.\d+)?)\s*days?", text, re.IGNORECASE)
        if days_match:
            params["autonomy_days"] = float(days_match.group(1))

        return params

    @classmethod
    def _extract_medical_parameters(cls, text: str) -> Dict[str, Any]:
        """Extracts weight and medication type from medical query."""
        params: Dict[str, Any] = {}

        wt_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:kg|kilos?|kilograms?|lbs?|pounds?)", text, re.IGNORECASE)
        if wt_match:
            val = float(wt_match.group(1))
            unit = wt_match.group(0).lower()
            if "lb" in unit or "pound" in unit:
                params["weight_kg"] = round(val / 2.20462, 1)
            else:
                params["weight_kg"] = val

        if "paracetamol" in text or "acetaminophen" in text:
            params["medication"] = "paracetamol"
        elif "ibuprofen" in text:
            params["medication"] = "ibuprofen"
        elif "ors" in text or "rehydration" in text:
            params["medication"] = "ors"

        return params

    @classmethod
    def _extract_electrical_parameters(cls, text: str) -> Dict[str, Any]:
        """Extracts voltage, current, length, and resistance from electrical query."""
        params: Dict[str, Any] = {}

        v_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:v|volts?)", text, re.IGNORECASE)
        if v_match:
            params["voltage"] = float(v_match.group(1))

        i_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:a|amps?|amperes?)", text, re.IGNORECASE)
        if i_match:
            params["current_a"] = float(i_match.group(1))

        len_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:m|meters?|metres?|ft|feet)", text, re.IGNORECASE)
        if len_match:
            val = float(len_match.group(1))
            unit = len_match.group(0).lower()
            if "ft" in unit or "feet" in unit:
                params["length_meters"] = round(val * 0.3048, 2)
            else:
                params["length_meters"] = val

        r_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:ohms?|Ω)", text, re.IGNORECASE)
        if r_match:
            params["resistance_ohm"] = float(r_match.group(1))

        return params
