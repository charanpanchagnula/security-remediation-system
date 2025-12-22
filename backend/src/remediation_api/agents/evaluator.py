from agno.agent import Agent
from ..services.llm_provider import get_provider
from ..models.remediation import RemediationResponse, EvaluationResult
from ..models.scan import Vulnerability
from ..logger import get_logger

logger = get_logger(__name__)

class EvaluatorAgent:
    def __init__(self):
        """
        Initializes the Evaluator Agent using the configured LLM provider.
        Defines the persona as a "Lead AppSec Reviewer".
        """
        self.agent = Agent(
            model=get_provider().get_model("deepseek-chat"),
            description="You are a Lead AppSec Reviewer. You are the gatekeeper for code quality and security.",
            instructions=[
                "Review the proposed remediation or false positive judgment for the vulnerability.",
                "EVALUATE FALSE POSITIVES: If the generator claims this is a false positive, verify this claim against the vulnerability type and context. If you agree, set 'is_false_positive' to true.",
                "SCORING CRITERIA:",
                "1. Completeness: Does it fix the root cause?",
                "2. Correctness: Is the syntax and logic correct?",
                "3. Security: Does it introduce new vulnerabilities?",
                "4. Confidence: Your overall certainty (0.0-1.0). If it's a False Positive claim, how sure are you?",
                "If you reject the fix (confidence < 0.7), provide specific instructions.",
                "Return ONLY the JSON object defined by the schema."
            ],
            output_schema=EvaluationResult,
            markdown=True
        )

    def evaluate_fix(self, vuln: Vulnerability, remediation: RemediationResponse) -> EvaluationResult:
        """
        Evaluates a proposed remediation for correctness, safety, and completeness.

        Args:
            vuln (Vulnerability): The original vulnerability.
            remediation (RemediationResponse): The proposed fix.

        Returns:
            EvaluationResult: The evaluation outcome (confidence score, feedback).
        """
        logger.info(f"Evaluating fix for {vuln.rule_id} (Summary: {remediation.summary[:50]}...)")
        prompt_context = f"""
INPUTS:
1. Original Vulnerability: {vuln.message} (Rule: {vuln.rule_id}, Scanner: {vuln.scanner})
2. Proposed Fix Summary: {remediation.summary}
3. Proposed Changes:
   {remediation.code_changes}
4. Explanation: {remediation.explanation}

EVALUATION CRITERIA:
1. EFFECTIVENESS: Does this actually remediate the specific vulnerability?
2. SAFETY: Does this fix introduce a regression or syntax error?
3. SIDE EFFECTS: Does strict input validation here break legitimate use cases?
"""
        response = self.agent.run(prompt_context)
        return response.content

evaluator_agent = EvaluatorAgent()
