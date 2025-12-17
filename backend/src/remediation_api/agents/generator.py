from agno.agent import Agent
from ..services.llm_provider import get_provider
from ..models.remediation import RemediationResponse
from ..models.scan import Vulnerability
from ..logger import get_logger

logger = get_logger(__name__)

class GeneratorAgent:
    def __init__(self):
        self.agent = Agent(
            model=get_provider().get_model("deepseek-chat"),
            description="You are a Staff Security Engineer specializing in secure coding practices.",
            instructions=[
                "Analyze the provided vulnerability and generate a secure, production-ready fix.",
                "EVALUATE FALSE POSITIVES: If the code is actually secure or the scanner is mistaken, set 'is_false_positive' to true and explain why in the 'explanation' field. Set 'code_changes' to an empty list in this case.",
                "STRICT REMEDIATION RULES:",
                "1. Only modify what is necessary to fix the security flaw.",
                "2. Match the indentation, variable naming convention, and commenting style of the original code.",
                "3. If the fix involves multiple files (e.g., Terraform module + variables), include ALL file changes in the `code_changes` list with exact relative file paths.",
                "4. Provide a 'Developer-to-Developer' explanation. Use Markdown formatting (bullet points, bold text) to make it readable and structured.",
                "5. Assign a 'confidence_score' between 0.0 and 1.0 based on how certain you are of the fix or the false positive judgment.",
                "Return ONLY the JSON object defined by the schema."
            ],
            output_schema=RemediationResponse,
            markdown=True
        )

    def generate_fix(self, vuln: Vulnerability, previous_feedback: list[str] = None, github_link: str = None) -> RemediationResponse:
        logger.info(f"Generating fix for {vuln.rule_id} (Feedback: {bool(previous_feedback)})")
        # Construct the prompt with context
        prompt_context = f"""
INPUT CONTEXT:
1. Vulnerability Metadata: Rule={vuln.rule_id}, Severity={vuln.severity}
2. File Location: {vuln.file_path} (Lines {vuln.start_line}-{vuln.end_line})
3. GitHub Link: {github_link or "N/A"}
4. Vulnerable Code:
   ```
   {vuln.code_snippet}
   ```
5. Surrounding Context:
   {vuln.surrounding_context}
6. Semgrep Rule ID: {vuln.rule_id}
7. Message: {vuln.message}
"""
        if previous_feedback:
            formatted_feedback = "\n".join(f"- {item}" for item in previous_feedback)
            prompt_context += f"\nPREVIOUS ATTEMPT FEEDBACK:\nThe previous fix was rejected. Please address the following:\n{formatted_feedback}\n"

        response = self.agent.run(prompt_context)
        return response.content

generator_agent = GeneratorAgent()
