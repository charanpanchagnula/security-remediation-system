from pydantic import BaseModel, Field
from typing import List, Optional, Literal

class CodeChange(BaseModel):
    file_path: str = Field(..., description="Relative path to the file")
    start_line: int = Field(..., description="Line number where change starts (1-indexed)")
    end_line: int = Field(..., description="Line number where change ends (1-indexed, inclusive)")
    original_code: str = Field(..., description="The code being replaced")
    new_code: str = Field(..., description="The secure replacement code")

class RemediationResponse(BaseModel):
    vulnerability_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    summary: str = Field(..., description="One sentence summary of the fix")
    explanation: str = Field(..., description="Detailed technical explanation of WHY this is a vulnerability and HOW the fix works")
    code_changes: List[CodeChange]
    security_implications: List[str] = Field(..., description="Potential side effects or security notes")
    is_false_positive: bool = Field(False, description="Whether the AI believes this is a false positive")
    confidence_score: float = Field(0.0, description="Confidence in the remediation or false positive judgment")

class EvaluationResult(BaseModel):
    completeness_score: float = Field(..., ge=0.0, le=1.0, description="Does it fix the root cause?")
    correctness_score: float = Field(..., ge=0.0, le=1.0, description="Is the syntax and logic correct?")
    security_score: float = Field(..., ge=0.0, le=1.0, description="Does it introduce new vulnerabilities?")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Overall confidence (average of above)")
    is_false_positive: bool = Field(False, description="If the evaluator deems the original finding invalid")
    is_approved: bool
    feedback: List[str] = Field(..., description="Specific, actionable feedback if rejected")
