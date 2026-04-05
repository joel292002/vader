from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


RiskLevel = Literal["critical", "high", "medium", "low", "info"]

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "output"


class PortFinding(BaseModel):
    port: int
    service: str
    banner: str
    risk: RiskLevel


class CVEFinding(BaseModel):
    cve_id: str
    severity: str
    description: str
    port: int
    service: str


class ReconResult(BaseModel):
    target: str
    hostname: str
    scan_start: str
    scan_end: str
    duration_seconds: float
    open_ports: list[PortFinding] = Field(default_factory=list)
    total_ports_scanned: int
    status: str = "complete"

    def save_json(self, filename: str | None = None) -> Path:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = OUTPUT_DIR / (filename or f"{self.target}_recon.json")
        output_path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return output_path


class VulnResult(BaseModel):
    target: str
    cves_found: list[CVEFinding] = Field(default_factory=list)
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    overall_risk: str
    status: str = "complete"

    def save_json(self, filename: str | None = None) -> Path:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = OUTPUT_DIR / (filename or f"{self.target}_vulns.json")
        output_path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return output_path


class SwarmResult(BaseModel):
    target: str
    recon: ReconResult
    vulns: VulnResult
    report_path: str
    swarm_duration_seconds: float
    status: str = "complete"
