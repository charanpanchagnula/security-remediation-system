# Security Remediation Intelligence System – Requirements Specification

## 1. Project Vision
To build a "Zero-Touch" security remediation platform that empowers developers to fix vulnerabilities instantly. By combining multi-scanner aggregation with agentic AI, the system reduces the "Mean Time to Remediation" (MTTR) from days to minutes. The core philosophy is **"Don't just find the bug—fix it."**

---

## 2. Functional Requirements

### 2.1 Authentication & User Management
*   **Secure Sign-In:** Users must authenticate via **Clerk** (supporting Email/Social Login) before accessing the dashboard.
*   **Session Management:** Protected routes for `/dashboard/*` to ensure data privacy.
*   **User Profile:** Access to profile settings and sign-out functionality via a unified header component.

### 2.2 Scan Management
*   **Scan Submission:** Users can trigger scans by providing a GitHub Repository URL.
*   **Multi-Scanner Support:** The system must orchestrate three distinct security engines:
    *   **Semgrep:** For Static Application Security Testing (SAST) to find code flaws.
    *   **Checkov:** For Infrastructure-as-Code (IaC) scanning (Terraform, Dockerfiles).
    *   **Trivy:** For Software Composition Analysis (SCA) to identify vulnerable dependencies.
*   **Real-Time Status:** Users must see the live status of scans (`Queued` -> `In Progress` -> `Completed`).
*   **History & Management:** Users can view a list of past scans and delete obsolete ones.

### 2.3 Vulnerability Intelligence
*   **Unified Dashboard:** Aggregated view of all findings, filterable by Scanner capability (SAST/IaC/SCA).
*   **Severity Sorting:** Critical and High severity issues must be prioritized at the top of the list.
*   **Detail View:** Clicking a finding displays the vulnerable code snippet, rule ID, and surrounding context.

### 2.4 Agentic AI Remediation
*   **On-Demand Generation:** Users can click "Generate AI Remediation" for any specific vulnerability.
*   **Batch Processing:** A "One-Click Fix All" button to asynchronously generate patches for every finding in the scan.
*   **Intelligent Fixes:**
    *   **Generator Agent:** Must produce a code patch along with a "Developer-to-Developer" Markdown explanation.
    *   **Context Awareness:** Fixes must respect the original code style (indentation, naming).
    *   **False Positive Detection:** The AI must actively evaluate if a finding is a False Positive. If so, it must flag it rather than hallucinatory fixing.

### 2.5 Quality Assurance (The Evaluator)
*   **Confidence Scoring:** Every remediation must have a reliability score (0-100%).
*   **Automated Review:** An isolated "Evaluator Agent" audits the fix for syntax errors, regressions, and security completeness.
*   **Automatic Rejection:** Fixes with low confidence (<70%) are automatically rejected and regenerated (Self-Healing Loop).

### 2.6 Knowledge Retention (Vector Store)
*   **RAG Architecture:** Successfully validated remediations are stored as embeddings in a Vector Database (S3/LanceDB).
*   **Reuse Logic:** Before generating a new fix, the system searches the vector store. If a similar vulnerability was solved previously, that solution is reused instantly, saving costs and ensuring consistency.

---

## 3. Non-Functional Requirements

*   **Scalability:** The backend uses an asynchronous worker pattern to handle multiple concurrent scans without performance degradation.
*   **Extensibility:** The "Scanner Service" is modular, allowing new tools (e.g., SonarQube) to be added with minimal code changes.
*   **Security:**
    *   No hardcoded credentials; extensive use of `.env` management.
    *   Secure storage of cloned repositories (ephemeral or sandboxed).
*   **User Experience:**
    *   Sub-second UI interactions using Optimistic Updates.
    *   Professional, "Dark Mode" first aesthetic.

---

## 4. Technology Stack

### Frontend
*   **Framework:** Next.js 14+ (Pages Router)
*   **Language:** TypeScript
*   **Styling:** Tailwind CSS + Lucide Icons
*   **Auth:** Clerk

### Backend
*   **API:** FastAPI (Python 3.11)
*   **Task Queue:** Custom AsyncIO Worker (simulating Celery/Redis for portability)
*   **AI Orchestration:** Agno Framework
*   **LLM:** DeepSeek V3 (Chat Model)

### Infrastructure & Data
*   **Vector Store:** Abstracted Interface (Local JSON for Dev / S3 for Prod)
*   **Database:** JSON-based Document Store (for portability)
*   **Deployment:** Docker / AWS App Runner ready
