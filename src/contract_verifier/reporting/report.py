"""Structured audit report schema and generator scaffold."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AuditReport:
    executive_summary: str
    threat_model: dict[str, object]
    invariants: list[dict[str, object]] = field(default_factory=list)
    vulnerability_hypotheses: list[dict[str, object]] = field(default_factory=list)
    confirmed_exploits: list[dict[str, object]] = field(default_factory=list)
    failed_hypotheses: list[dict[str, object]] = field(default_factory=list)
    potential_risks: list[dict[str, object]] = field(default_factory=list)
    verified_properties: list[dict[str, object]] = field(default_factory=list)
    counterexamples: list[dict[str, object]] = field(default_factory=list)
    escalation_chains: list[dict[str, object]] = field(default_factory=list)
    remediation: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "executive_summary": self.executive_summary,
            "threat_model": self._normalize_mapping(self.threat_model),
            "invariants": self._normalize_records(self.invariants),
            "vulnerability_hypotheses": self._normalize_records(self.vulnerability_hypotheses),
            "confirmed_exploits": self._normalize_records(self.confirmed_exploits),
            "failed_hypotheses": self._normalize_records(self.failed_hypotheses),
            "potential_risks": self._normalize_records(self.potential_risks),
            "verified_properties": self._normalize_records(self.verified_properties),
            "counterexamples": self._normalize_records(self.counterexamples),
            "escalation_chains": self._normalize_records(self.escalation_chains),
            "remediation": self._normalize_records(self.remediation),
        }

    def to_markdown(self) -> str:
        data = self.to_dict()
        sections = [
            "# Audit Report",
            "",
            "## Executive Summary",
            str(data["executive_summary"]),
            "",
            "## Threat Model",
            self._format_mapping(data["threat_model"]),
            "",
            "## Invariants",
            self._format_records(data["invariants"]),
            "",
            "## Vulnerability Hypotheses",
            self._format_records(data["vulnerability_hypotheses"]),
            "",
            "## Confirmed Exploits",
            self._format_records(data["confirmed_exploits"]),
            "",
            "## Failed Hypotheses",
            self._format_records(data["failed_hypotheses"]),
            "",
            "## Potential Risks",
            self._format_records(data["potential_risks"]),
            "",
            "## Verified Properties",
            self._format_records(data["verified_properties"]),
            "",
            "## Counterexamples",
            self._format_records(data["counterexamples"]),
            "",
            "## Escalation Chains",
            self._format_records(data["escalation_chains"]),
            "",
            "## Remediation",
            self._format_records(data["remediation"]),
        ]
        return "\n".join(sections).rstrip() + "\n"

    def _normalize_records(self, records: list[dict[str, object]]) -> list[dict[str, object]]:
        return [self._normalize_mapping(record) for record in sorted(records, key=self._record_sort_key)]

    def _record_sort_key(self, record: dict[str, object]) -> tuple[str, str]:
        for key in ("id", "obligation_id", "property_id", "title"):
            if key in record:
                return key, str(record[key])
        return "", repr(sorted(record.items()))

    def _normalize_mapping(self, value: dict[str, object]) -> dict[str, object]:
        normalized: dict[str, object] = {}
        for key in sorted(value):
            item = value[key]
            if isinstance(item, dict):
                normalized[key] = self._normalize_mapping(item)
            elif isinstance(item, list):
                normalized[key] = [
                    self._normalize_mapping(entry) if isinstance(entry, dict) else entry
                    for entry in item
                ]
            else:
                normalized[key] = item
        return normalized

    def _format_mapping(self, mapping: object) -> str:
        if not isinstance(mapping, dict) or not mapping:
            return "- None"
        return "\n".join(f"- **{key}**: {mapping[key]}" for key in sorted(mapping))

    def _format_records(self, records: object) -> str:
        if not isinstance(records, list) or not records:
            return "- None"
        lines: list[str] = []
        for record in records:
            if not isinstance(record, dict):
                lines.append(f"- {record}")
                continue
            title = record.get("id") or record.get("obligation_id") or record.get("title") or "record"
            details = ", ".join(f"{key}={record[key]}" for key in sorted(record) if key != "id")
            lines.append(f"- **{title}**" + (f": {details}" if details else ""))
        return "\n".join(lines)


class ReportGenerator:
    def empty(self) -> AuditReport:
        return AuditReport(
            executive_summary="No verification results supplied.",
            threat_model={"principals": [], "assets": [], "trust_boundaries": []},
        )
