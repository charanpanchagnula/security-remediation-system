from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class TraceNode(BaseModel):
    """Represents a step in a data flow trace (for source-to-sink analysis)."""
    file_path: str = Field(..., description="File where this step occurs")
    line_number: int = Field(..., description="Line number")
    code_snippet: str = Field(..., description="Code at this step")
    step_description: str = Field(default="", description="Description of the data flow event (e.g. 'User input', 'Sanitization')")

class Vulnerability(BaseModel):
    """Normalized vulnerability finding from a scanner."""
    id: str = Field(..., description="Unique ID for this specific finding instance")
    rule_id: str = Field(..., description="Scanner rule identifier (e.g. python.lang.security.audit.exec)")
    message: str = Field(..., description="Scanner description of the issue")
    severity: str = Field(..., description="Severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
    
    scanner: str = Field(..., description="Scanner that found this issue (e.g. semgrep, checkov, trivy)")
    file_path: str
    start_line: int
    end_line: int
    
    code_snippet: str = Field(..., description="The vulnerable code itself")
    surrounding_context: str = Field(..., description="Lines of code around the vulnerability")
    
    # New Field for Enterprise Scanners (Checkmarx, Semgrep Pro)
    taint_trace: List[TraceNode] = Field(default_factory=list, description="Ordered list of steps from source to sink")
    
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional scanner-specific metadata")

class ScanResult(BaseModel):
    scan_id: str
    repo_url: str
    timestamp: str
    vulnerabilities: List[Vulnerability]
