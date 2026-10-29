"""Knowledge Grounding Harness & Direct Offline Engine (F-11, F-12).

Active RAG pipeline supporting both AI-grounded inference with clickable citations
and direct, zero-token offline encyclopedia / curriculum browsing.
Couples with Deterministic Safety Calculators (F-13..F-16) and Source-Verification Audit (F-17).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union

from emyrge.core.config import EmyrgeError
from emyrge.knowledge.zim_reader import ZimReader, ArticleSnippet, ArticleContent
from emyrge.knowledge.khan_curriculum import KhanCurriculum, LessonSnippet, LessonContent
from emyrge.calculators.source_audit import SourceAudit, AuditReport, CalculatorRouter
from emyrge.calculators.water_purification import WaterCalculator
from emyrge.calculators.solar_battery import SolarCalculator
from emyrge.calculators.medical_rehydration import MedicalCalculator
from emyrge.calculators.electrical_formulas import ElectricalCalculator


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class HarnessError(EmyrgeError):
    """Base exception for AI knowledge grounding harness failures."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__("ERR_HARNESS_GENERAL", message, details)


class CitationFormatError(HarnessError):
    """Raised when generated citations violate the strict regex syntax contract."""
    def __init__(self, invalid_tag: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"Invalid citation syntax: {invalid_tag}", details or {"tag": invalid_tag})
        self.code = "ERR_CITATION_SYNTAX"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class CitationType(str, Enum):
    """Citation category: ZIM article section vs Khan Academy lesson."""
    SOURCE = "Source"
    LESSON = "Lesson"


class HarnessMode(str, Enum):
    """Execution mode for user knowledge queries."""
    HARNESS = "harness"
    NON_HARNESS = "non_harness"
    DIRECT = "direct"


@dataclass
class Citation:
    """Structured clickable citation referencing verified offline knowledge."""
    citation_type: CitationType
    target: str
    section_or_topic: Optional[str] = None
    raw_tag: str = ""

    def __post_init__(self):
        if not self.raw_tag:
            type_val = self.citation_type.value if isinstance(self.citation_type, CitationType) else str(self.citation_type)
            if type_val == "Source":
                sec_part = f"#{self.section_or_topic}" if self.section_or_topic else ""
                self.raw_tag = f"[Source: {self.target}{sec_part}]"
            else:
                # Khan format: [Lesson: Subject/Topic]
                if self.section_or_topic:
                    self.raw_tag = f"[Lesson: {self.target}/{self.section_or_topic}]"
                else:
                    self.raw_tag = f"[Lesson: {self.target}]"

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            val = getattr(self, item)
            if isinstance(val, CitationType):
                return val.value
            return val
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "citation_type": self.citation_type.value if isinstance(self.citation_type, CitationType) else str(self.citation_type),
            "target": self.target,
            "section_or_topic": self.section_or_topic,
            "raw_tag": self.raw_tag,
        }


@dataclass
class GroundedSource:
    """Passage retrieved from offline knowledge for prompt grounding."""
    source_type: str  # "zim", "khan", "vault", "calculator"
    title: str
    url_or_id: str
    snippet: str
    section_or_topic: Optional[str] = None
    full_text: Optional[str] = None
    score: float = 0.0

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "title": self.title,
            "url_or_id": self.url_or_id,
            "snippet": self.snippet,
            "section_or_topic": self.section_or_topic,
            "score": round(self.score, 3),
        }


class GroundingContext(list):
    """Assembled context payload injected into the adaptive prompt pipeline."""

    def __init__(
        self,
        query: str = "",
        sources: Optional[List[GroundedSource]] = None,
        combined_context_text: str = "",
    ) -> None:
        srcs = list(sources or [])
        super().__init__(srcs)
        self.query = query
        self.sources = srcs
        self.combined_context_text = combined_context_text

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "sources": [s.to_dict() if hasattr(s, "to_dict") else s for s in self],
            "combined_context_text": self.combined_context_text,
        }


@dataclass
class GroundedResponse:
    """Complete response returned by GroundingHarness for UI / Mesh consumption."""
    query: str
    mode: str
    answer: str
    citations: List[Citation] = field(default_factory=list)
    sources: List[GroundedSource] = field(default_factory=list)
    audit_passed: bool = True
    audit_flags: List[Dict[str, Any]] = field(default_factory=list)
    annotated_answer: str = ""

    def __post_init__(self):
        if not self.annotated_answer:
            self.annotated_answer = self.answer

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "mode": self.mode,
            "answer": self.answer,
            "citations": [c.to_dict() if hasattr(c, "to_dict") else c for c in self.citations],
            "sources": [s.to_dict() if hasattr(s, "to_dict") else s for s in self.sources],
            "audit_passed": self.audit_passed,
            "audit_flags": self.audit_flags,
            "annotated_answer": self.annotated_answer,
        }


@dataclass
class NonHarnessSearchResult:
    """Unified search result for direct, AI-free article and lesson lookup."""
    query: str
    zim_results: List[ArticleSnippet] = field(default_factory=list)
    khan_results: List[LessonSnippet] = field(default_factory=list)
    total_count: int = 0

    def __post_init__(self):
        if not self.total_count:
            self.total_count = len(self.zim_results) + len(self.khan_results)

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "zim_results": [z.to_dict() if hasattr(z, "to_dict") else z for z in self.zim_results],
            "khan_results": [k.to_dict() if hasattr(k, "to_dict") else k for k in self.khan_results],
            "total_count": self.total_count,
        }


@dataclass
class DirectContent:
    """Raw, un-summarized knowledge payload for direct reading."""
    content_type: str  # "zim" or "khan"
    id_or_path: str
    title: str
    html_body: str
    raw_text: str
    mime_type: str = "text/html"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content_type": self.content_type,
            "id_or_path": self.id_or_path,
            "title": self.title,
            "html_body": self.html_body,
            "raw_text": self.raw_text,
            "mime_type": self.mime_type,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# GroundingHarness Implementation
# ---------------------------------------------------------------------------

class GroundingHarness:
    """Unified offline knowledge harness supporting both AI-grounded and direct modes."""

    # Authoritative Citation Regex: [Source: <Title>#<Section>] or [Lesson: <Subject>/<Topic>]
    CITATION_PATTERN = re.compile(r"\[(Source|Lesson):\s*([^#\]]+)(?:#([^\]]+))?\]")

    def __init__(
        self,
        zim_reader: Optional[Any] = None,
        khan_curriculum: Optional[KhanCurriculum] = None,
        model_runner: Optional[Any] = None,
        source_audit: Optional[Any] = None,
        memory_db: Optional[Any] = None,
    ) -> None:
        if zim_reader is not None and not isinstance(zim_reader, ZimReader) and hasattr(zim_reader, "project_root"):
            cfg = zim_reader
            from emyrge.knowledge.seed_corpus import DEFAULT_ZIM_ARTICLES
            self.zim_reader: Optional[ZimReader] = ZimReader(data_dir=cfg.zim_dir, fallback_articles=DEFAULT_ZIM_ARTICLES)
            self.khan_curriculum: Optional[KhanCurriculum] = KhanCurriculum(cfg.project_root)
            self.model_runner: Optional[Any] = model_runner
            self.source_audit: Optional[Any] = source_audit or SourceAudit
            self.memory_db: Optional[Any] = memory_db
        else:
            self.zim_reader = zim_reader
            self.khan_curriculum = khan_curriculum
            self.model_runner = model_runner
            self.source_audit = source_audit or SourceAudit
            self.memory_db = memory_db

    @staticmethod
    def resolve_prompting_strategy(tier: Any) -> Any:
        """Determines the adaptive prompt strategy based on hardware capability tier."""
        from emyrge.core.config import HardwareTier, PromptingStrategy
        tier_val = getattr(tier, "value", tier)
        if tier in (HardwareTier.TIER_0, HardwareTier.THIN_CLIENT, 0, "0", "tier_0"):
            return PromptingStrategy.SEARCH_THEN_SUMMARIZE
        return PromptingStrategy.TOOL_CALLING

    def retrieve_context(self, query: str, limit: int = 5) -> GroundingContext:
        """Retrieves relevant passages across ZIM reader, Khan curriculum, and verified memory notes."""
        if not query or not query.strip():
            return GroundingContext(query=query, sources=[], combined_context_text="")

        sources: List[GroundedSource] = []

        # 1. Search verified memory notes if SQLite memory_db is attached (PRD_ARD §4.1)
        if self.memory_db:
            try:
                cur = self.memory_db.cursor()
                # Query verified_master_notes
                cur.execute(
                    "SELECT topic, content, citations FROM verified_master_notes WHERE topic LIKE ? OR content LIKE ? LIMIT 2",
                    (f"%{query}%", f"%{query}%"),
                )
                for row in cur.fetchall():
                    sources.append(
                        GroundedSource(
                            source_type="vault",
                            title=row[0] if isinstance(row, tuple) else row["topic"],
                            url_or_id=f"vault/{row[0] if isinstance(row, tuple) else row['topic']}",
                            snippet=(row[1] if isinstance(row, tuple) else row["content"])[:250],
                            section_or_topic="Verified Master Note",
                            full_text=row[1] if isinstance(row, tuple) else row["content"],
                            score=1.1,  # Highest priority for verified human/docked notes
                        )
                    )
            except Exception:
                pass

        # 2. Search ZIM articles
        if self.zim_reader and self.zim_reader.is_available():
            zim_matches = self.zim_reader.search(query, limit=limit)
            for z in zim_matches:
                full_art = self.zim_reader.get_article(z.url)
                full_text = full_art.text_content if full_art else z.snippet
                sources.append(
                    GroundedSource(
                        source_type="zim",
                        title=z.title,
                        url_or_id=z.url,
                        snippet=z.snippet,
                        section_or_topic=z.section,
                        full_text=full_text,
                        score=z.score,
                    )
                )

        # 3. Search Khan curriculum
        if self.khan_curriculum:
            khan_matches = self.khan_curriculum.search(query, limit=limit)
            for k in khan_matches:
                full_lesson = self.khan_curriculum.get_lesson(k.lesson_id)
                full_text = full_lesson.content if full_lesson else k.snippet
                sources.append(
                    GroundedSource(
                        source_type="khan",
                        title=k.title,
                        url_or_id=k.lesson_id,
                        snippet=k.snippet,
                        section_or_topic=f"{k.subject}/{k.topic}",
                        full_text=full_text,
                        score=0.85,
                    )
                )

        # Sort combined sources by score descending
        sources.sort(key=lambda s: s.score, reverse=True)
        top_sources = sources[:limit]

        combined_text = "\n\n".join(
            f"[{s.source_type.upper()}: {s.title}]\n{s.full_text or s.snippet}" for s in top_sources
        )

        return GroundingContext(
            query=query,
            sources=top_sources,
            combined_context_text=combined_text,
        )

    def format_citations(self, sources: List[GroundedSource]) -> List[Citation]:
        """Converts retrieved sources into standard clickable citation tags."""
        citations: List[Citation] = []
        for s in sources:
            if s.source_type == "zim":
                citations.append(
                    Citation(
                        citation_type=CitationType.SOURCE,
                        target=s.title,
                        section_or_topic=s.section_or_topic,
                    )
                )
            elif s.source_type == "khan":
                # For Khan curriculum: [Lesson: <Subject>/<Topic>]
                if s.section_or_topic and "/" in s.section_or_topic:
                    subj, topic = s.section_or_topic.split("/", 1)
                    citations.append(
                        Citation(
                            citation_type=CitationType.LESSON,
                            target=subj,
                            section_or_topic=topic,
                        )
                    )
                else:
                    citations.append(
                        Citation(
                            citation_type=CitationType.LESSON,
                            target=s.title,
                            section_or_topic=s.section_or_topic,
                        )
                    )
            elif s.source_type == "vault":
                citations.append(
                    Citation(
                        citation_type=CitationType.SOURCE,
                        target=s.title,
                        section_or_topic="Verified Master Note",
                    )
                )
        return citations

    def parse_citations(self, text: str) -> List[Citation]:
        """Extracts and parses all citation tags present in text matching CITATION_PATTERN."""
        citations: List[Citation] = []
        if not text:
            return citations

        for match in self.CITATION_PATTERN.finditer(text):
            ctype_str, target, section = match.groups()
            ctype = CitationType.SOURCE if ctype_str.lower() == "source" else CitationType.LESSON
            target = target.strip()
            section = section.strip() if section else None

            # If Khan lesson has target like "Physics/Forces and Newton's Laws"
            if ctype == CitationType.LESSON and "/" in target:
                subj, top = target.split("/", 1)
                citations.append(
                    Citation(
                        citation_type=ctype,
                        target=subj.strip(),
                        section_or_topic=top.strip(),
                        raw_tag=match.group(0),
                    )
                )
            else:
                citations.append(
                    Citation(
                        citation_type=ctype,
                        target=target,
                        section_or_topic=section,
                        raw_tag=match.group(0),
                    )
                )

        return citations

    def query(
        self,
        user_query: str,
        mode: str = "harness",
        max_sources: int = 5,
    ) -> GroundedResponse:
        """Primary entry point for knowledge queries.

        Modes:
        - 'harness': Retrieves offline context, checks safety calculators, prompts AI model,
          audits numerical claims, and returns GroundedResponse with validated clickable citations.
        - 'non_harness' / 'direct': Bypasses AI completely, performs direct index lookup,
          and returns exact text/HTML snippets with zero token generation latency.
        """
        if not user_query or not user_query.strip():
            return GroundedResponse(
                query=user_query,
                mode=mode,
                answer="Please provide a valid question or search query.",
                citations=[],
                sources=[],
                audit_passed=True,
                audit_flags=[],
                annotated_answer="Please provide a valid question or search query.",
            )

        norm_mode = mode.lower()

        # -------------------------------------------------------------------
        # Mode: Non-Harness / Direct (F-12)
        # -------------------------------------------------------------------
        if norm_mode in ("non_harness", "direct"):
            ctx = self.retrieve_context(user_query, limit=max_sources)
            if not ctx.sources:
                return GroundedResponse(
                    query=user_query,
                    mode="non_harness",
                    answer="No offline articles or lessons matched your search query.",
                    citations=[],
                    sources=[],
                    audit_passed=True,
                    audit_flags=[],
                    annotated_answer="No offline articles or lessons matched your search query.",
                )

            top = ctx.sources[0]
            answer_text = top.full_text or top.snippet
            citations = self.format_citations([top])
            if citations:
                answer_text = f"{answer_text} {citations[0].raw_tag}"

            return GroundedResponse(
                query=user_query,
                mode="non_harness",
                answer=answer_text,
                citations=citations,
                sources=ctx.sources,
                audit_passed=True,
                audit_flags=[],
                annotated_answer=answer_text,
            )

        # -------------------------------------------------------------------
        # Mode: Harness (F-11)
        # -------------------------------------------------------------------
        # Step 1: Safety intent classification and calculator pre-computation (F-18)
        route_info = CalculatorRouter.analyze_query(user_query)
        calc_source: Optional[GroundedSource] = None

        if route_info.route != "general":
            try:
                calc_result = self._execute_calculator(route_info.route, route_info.extracted_parameters)
                if calc_result:
                    calc_summary = self._format_calculator_context(route_info.route, calc_result)
                    calc_source = GroundedSource(
                        source_type="calculator",
                        title=f"{route_info.route.capitalize()} Calculator Oracle",
                        url_or_id=f"calc://{route_info.route}",
                        snippet=calc_summary,
                        section_or_topic="Deterministic Safe Dosage",
                        full_text=calc_summary,
                        score=2.0,  # Highest score
                    )
            except Exception:
                pass

        # Step 2: Retrieve offline knowledge
        ctx = self.retrieve_context(user_query, limit=max_sources)
        all_sources = list(ctx.sources)
        if calc_source:
            all_sources.insert(0, calc_source)

        if not all_sources:
            msg = "No matching offline knowledge found for this query in the local repository."
            return GroundedResponse(
                query=user_query,
                mode="harness",
                answer=msg,
                citations=[],
                sources=[],
                audit_passed=True,
                audit_flags=[],
                annotated_answer=msg,
            )

        citations = self.format_citations([s for s in all_sources if s.source_type != "calculator"])

        # Step 3: Generate draft response
        draft_answer = ""
        if self.model_runner and hasattr(self.model_runner, "complete"):
            try:
                prompt = f"Grounding Context:\n{ctx.combined_context_text}\n\nQuestion: {user_query}\nAnswer with citations:"
                draft_answer = self.model_runner.complete(prompt, max_tokens=256)
            except Exception:
                draft_answer = ""

        if not draft_answer:
            # Deterministic knowledge synthesis fallback for zero-install / micro-tier
            top_knowledge = next((s for s in all_sources if s.source_type in ("zim", "khan", "vault")), all_sources[0])
            cit_tag = citations[0].raw_tag if citations else ""
            if calc_source:
                draft_answer = f"{calc_source.snippet} According to offline references: {top_knowledge.snippet} {cit_tag}".strip()
            else:
                draft_answer = f"{top_knowledge.snippet} {cit_tag}".strip()

        # Step 4: Run Source-Verification Audit Pass (F-17)
        source_texts = [s.full_text or s.snippet for s in all_sources]
        audit_report = SourceAudit.audit(draft_answer, source_texts)

        # Step 5: Parse citations from draft answer or attach formatted ones
        present_citations = self.parse_citations(draft_answer)
        final_citations = present_citations if present_citations else citations

        return GroundedResponse(
            query=user_query,
            mode="harness",
            answer=draft_answer,
            citations=final_citations,
            sources=all_sources,
            audit_passed=audit_report.is_clean,
            audit_flags=[f.to_dict() if hasattr(f, "to_dict") else f for f in audit_report.flagged_claims],
            annotated_answer=audit_report.annotated_text,
        )

    def _execute_calculator(self, route: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Executes the deterministic calculator for the specified route."""
        if route == "water":
            vol = params.get("volume_liters", 1.0)
            turbid = params.get("is_turbid", False)
            method = params.get("method", "bleach")
            if method == "iodine":
                return WaterCalculator.calculate_iodine(vol, is_turbid=turbid)
            return WaterCalculator.calculate_bleach(vol, is_turbid=turbid)
        elif route == "solar":
            wh = params.get("daily_wh", 600.0)
            v = params.get("system_voltage", 12.0)
            days = params.get("autonomy_days", 1.0)
            return SolarCalculator.calculate_system(daily_wh=wh, system_voltage=v, autonomy_days=days)
        elif route == "medical":
            wt = params.get("weight_kg", 10.0)
            med = params.get("medication", "paracetamol")
            if med == "ors":
                return MedicalCalculator.calculate_ors(wt)
            elif med == "ibuprofen":
                return MedicalCalculator.calculate_ibuprofen(wt)
            return MedicalCalculator.calculate_paracetamol(wt)
        elif route == "electrical":
            v = params.get("voltage")
            i = params.get("current_a")
            r = params.get("resistance_ohm")
            if (v is not None and i is not None) or (v is not None and r is not None) or (i is not None and r is not None):
                return ElectricalCalculator.solve_ohms_law(v=v, i=i, r=r)
        return None

    def _format_calculator_context(self, route: str, calc_res: Dict[str, Any]) -> str:
        """Formats calculator oracle output for inclusion in grounding context."""
        if route == "water":
            return (
                f"Authoritative Water Dosing: For {calc_res.get('volume_liters')} liters "
                f"({'turbid' if calc_res.get('is_turbid') else 'clear'} water), "
                f"add {calc_res.get('drops')} drops ({calc_res.get('volume_ml')} ml) of bleach. "
                f"Wait at least {calc_res.get('contact_time_minutes')} minutes."
            )
        elif route == "solar":
            return (
                f"Authoritative Solar Sizing: For {calc_res.get('daily_wh')} Wh daily load at "
                f"{calc_res.get('system_voltage')}V, required battery capacity is "
                f"{calc_res.get('battery_capacity_ah')} ah and solar PV array is "
                f"{calc_res.get('solar_array_watts')} watts."
            )
        elif route == "medical":
            med = calc_res.get("medication", "medication")
            if "total_ors_ml_4h" in calc_res:
                return (
                    f"Authoritative Medical Dosing: Administer {calc_res.get('total_ors_ml_4h')} ml ORS "
                    f"over 4 hours for {calc_res.get('weight_kg')} kg patient."
                )
            return (
                f"Authoritative Medical Dosing: Recommended {med} single dose is "
                f"{calc_res.get('single_dose_mg')} mg every {calc_res.get('interval_hours')} hours."
            )
        elif route == "electrical":
            return (
                f"Authoritative Electrical Calculation: Voltage {calc_res.get('voltage_v')} volts, "
                f"Current {calc_res.get('current_a')} amps, Resistance {calc_res.get('resistance_ohm')} ohms, "
                f"Power {calc_res.get('power_w')} watts."
            )
        return str(calc_res)

    def direct_search(self, query: str, limit: int = 10) -> NonHarnessSearchResult:
        """Performs unified direct search across ZIM articles and Khan curriculum."""
        zim_results: List[ArticleSnippet] = []
        khan_results: List[LessonSnippet] = []

        if self.zim_reader and self.zim_reader.is_available():
            zim_results = self.zim_reader.search(query, limit=limit)

        if self.khan_curriculum:
            khan_results = self.khan_curriculum.search(query, limit=limit)

        return NonHarnessSearchResult(
            query=query,
            zim_results=zim_results,
            khan_results=khan_results,
            total_count=len(zim_results) + len(khan_results),
        )

    def get_direct_content(self, content_type: str, content_id: str) -> Optional[DirectContent]:
        """Fetches raw content payload for direct reading without AI summarization."""
        c_type = content_type.strip().lower()

        if c_type == "zim":
            if not self.zim_reader:
                return None
            art = self.zim_reader.get_article(content_id)
            if not art:
                return None
            return DirectContent(
                content_type="zim",
                id_or_path=art.url,
                title=art.title,
                html_body=art.html_content,
                raw_text=art.text_content,
                mime_type=art.mime_type,
                metadata=art.metadata,
            )
        elif c_type == "khan":
            if not self.khan_curriculum:
                return None
            lesson = self.khan_curriculum.get_lesson(content_id)
            if not lesson:
                return None
            html_body = f"<html><head><title>{lesson.title}</title></head><body><h1>{lesson.title}</h1><p>{lesson.content}</p></body></html>"
            return DirectContent(
                content_type="khan",
                id_or_path=lesson.lesson_id,
                title=lesson.title,
                html_body=html_body,
                raw_text=lesson.content,
                mime_type="text/html",
                metadata={"subject": lesson.subject, "topic": lesson.topic, "exercises_count": len(lesson.exercises)},
            )

        return None
