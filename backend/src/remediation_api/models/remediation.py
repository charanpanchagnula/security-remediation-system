from pydantic import BaseModel, Field
from typing import List, Optional, Literal

class CodeChange(BaseModel):
    file_path: str = Field(..., description="Relative path to the file")
    start_line: int = Field(..., description="Line number where change starts (1-indexed)")
    end_line: int = Field(..., description="Line number where change ends (1-indexed, inclusive)")
    original_code: str = Field(..., description="The code being replaced")
    new_code: str = Field(..., description="The secure replacement code")
    description: str = Field("", description="Why this specific change fixes the issue")

class RemediationResponse(BaseModel):
    vulnerability_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    summary: str = Field(..., description="One sentence summary of the fix")
    explanation: str = Field(..., description="Detailed technical explanation of WHY this is a vulnerability and HOW the fix works")
    code_changes: List[CodeChange]
    security_implications: List[str] = Field(..., description="Potential side effects or security notes")
    evaluation_concerns: List[str] = Field(default_factory=list, description="Any concerns found during self-evaluation that could not be resolved")
    is_false_positive: bool = Field(False, description="Whether the AI believes this is a false positive")
    confidence_score: float = Field(0.0, description="Confidence in the remediation or false positive judgment")
    security_reasoning: dict = Field(default_factory=dict)
    iterations_used: int = Field(0, description="Number of validate_and_scan iterations the agent used")
    max_iterations: int = Field(0, description="Max iterations the agent was allowed")
