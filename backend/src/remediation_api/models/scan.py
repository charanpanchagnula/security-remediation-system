from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class TraceNode(BaseModel):
    """Represents a step in a data flow trace (for source-to-sink analysis)."""
    file_path: str = Field(..., description="File where this step occurs")
    line_number: int = Field(..., description="Line number")
    code_snippet: str = Field(..., description="Code at this step")
    step_description: str = Field(default="", description="Description of the data flow event")


class Vulnerability(BaseModel):
    """Normalized vulnerability finding from a scanner."""
    id: str = Field(..., description="Unique ID for this specific finding instance")
    rule_id: str = Field(..., description="Scanner rule identifier")
    message: str = Field(..., description="Scanner description of the issue")
    severity: str = Field(..., description="Severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)")

    scanner: str = Field(..., description="Scanner that found this issue")
    file_path: str
    start_line: int
    end_line: int

    code_snippet: str = Field(..., description="The vulnerable code itself")
    surrounding_context: str = Field(..., description="Lines of code around the vulnerability")

    taint_trace: List[TraceNode] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScannerJob(BaseModel):
    """Tracks the status of one scanner within a session."""
    scanner: str = Field(..., description="Scanner name (semgrep, checkov, trivy, checkmarx...)")
    status: str = Field(default="queued", description="queued | in_progress | completed | failed")
    internal_scan_id: Optional[str] = Field(default=None, description="External/vendor scan ID if applicable")
    vuln_count: int = Field(default=0)


class ScanResult(BaseModel):
    scan_id: str                          # Session-level identifier (overarching)
    project_name: Optional[str] = None   # e.g. "payments-api"
    author: Optional[str] = None         # Developer who triggered the scan
    source: str = Field(default="web", description="Trigger source: cli | mcp | web | grc")
    repo_url: str
    branch: Optional[str] = "main"
    commit_sha: Optional[str] = None
    timestamp: str
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    scanner_jobs: List[ScannerJob] = Field(default_factory=list)
