# Security Remediation Intelligence System – Requirements Specification

## 1. Project Vision
To build a **"Zero-Touch"** security remediation platform that empowers developers to fix vulnerabilities instantly. By combining multi-scanner aggregation with agentic AI, the system reduces the **"Mean Time to Remediation" (MTTR)** from days to minutes. The core philosophy is **"Don't just find the bug—fix it."**

---

## 2. Functional Requirements

### 2.1 Authentication & User Management
*   **Client-Side Authentication:** Users authenticate via **Clerk** using the `@clerk/clerk-react` SDK to support Single Page Application (SPA) architecture.
*   **Static Export Compatibility:** All auth checks occur in the browser (Client Components) rather than on the server (Middleware), enabling full compatibility with Docker static hosting.
*   **Session Management:** Protected routes for `/dashboard/*` redirect unauthenticated users to the sign-in page immediately upon load.
*   **User Profile:** Unified header component provides access to profile settings and sign-out functionality.

### 2.2 Scan Management
*   **Scan Submission:** Users can trigger scans by providing a GitHub Repository URL.
*   **Multi-Scanner Support:** The system orchestrates three distinct security engines via a unified interface:
    *   **Semgrep:** For **Static Application Security Testing (SAST)** code flaws and **MCP (Model Context Protocol)** security scanning.
    *   **Checkov:** For Infrastructure-as-Code (IaC) scanning (Terraform, Dockerfiles).
    *   **Trivy:** For Software Composition Analysis (SCA) to identify vulnerable dependencies.
*   **Async Processing:** Scans are queued and processed asynchronously by a dedicated backend worker to prevent timeout issues.
*   **History & Management:** Users can view a list of past scans, see their live status (`Queued` -> `In Progress` -> `Completed`), and delete obsolete results.

### 2.3 Vulnerability Intelligence
*   **Unified Dashboard:** Aggregated view of all findings, filterable by Scanner capability (SAST/IaC/SCA).
*   **Severity Sorting:** Critical and High severity issues are prioritized at the top.
*   **Scan Detail View:** A dedicated static page (`/dashboard/scan/view?id=...`) displays the specific vulnerability details, including code snippets and rule IDs, using query parameters for routing.

### 2.4 Agentic AI Remediation
*   **On-Demand Generation:** Users can click "Generate AI Remediation" for specific vulnerabilities.
*   **Intelligent Fixes:**
    *   **Generator Agent:** LLM (DeepSeek V3/OpenAI) produces a code patch and a markdown explanation.
    *   **Context Awareness:** Fixes respect the original code style and structure.
    *   **False Positive Detection:** The AI evaluates findings and can flag them as False Positives instead of generating unnecessary code.

### 2.5 Quality Assurance (The Evaluator)
*   **Confidence Scoring:** Every remediation is assigned a reliability score.
*   **Automated Review:** An "Evaluator Agent" audits the generated fix for syntax errors and security consistency.
*   **Self-Healing Loop:** Fixes with low confidence are automatically rejected and regenerated to ensure quality.

### 2.6 Knowledge Retention (Vector Store)
*   **RAG Architecture:** Validated remediations are stored as embeddings.
*   **Reuse Logic:** The system searches the vector store before generating new fixes to reuse proven solutions for recurrent vulnerabilities.

---

## 3. Non-Functional Requirements

### 3.1 Architecture & Deployment
*   **Static Frontend:** The storage and serving model relies on **Next.js Static Export** (`output: 'export'`). This decouples the frontend from a Node.js runtime, allowing it to be served purely as static assets by the Python backend.
*   **Containerization:** The entire application (Frontend + Backend) is packaged into a **single Docker container** based on `python:3.12-slim`.
*   **Secure Context:** The application enforces **HTTPS/Localhost** usage to ensure browser security features (like Web Crypto API for Auth) function correctly.

### 3.2 Performance & Scalability
*   **Async Worker Pattern:** A decoupled worker process manages heavy scanning tasks, ensuring the API remains responsive.
*   **Local-First Design:** Supports a `local_mock` environment for development (using in-memory queues and local file storage) while being architected to switch to SQS/S3 for production.

### 3.3 Security
*   **Environment Management:** Strict separation of build-time (public keys) and runtime (secret keys) environment variables.
*   **Sandboxed Scans:** Cloned repositories are processed in ephemeral directories (`/tmp`) to prevent data persistence issues.

---

## 4. Technology Stack

### Frontend
*   **Framework:** Next.js 16 (App Router with Static Export)
*   **Language:** TypeScript
*   **Styling:** Tailwind CSS + Lucide Icons
*   **Auth:** Clerk (React SDK)
*   **State:** React Hooks (`useEffect`, `useState`)

### Backend
*   **API:** FastAPI (Python 3.12)
*   **Task Queue**: Custom AsyncIO Worker (Local File Queue / AWS SQS)
*   **AI Orchestration:** Agno Framework (with DeepSeek/OpenAI models)
*   **Scanner Tools:** Semgrep, Checkov, Trivy (CLI binaries installed in container)

### Infrastructure & Data
*   **Storage:** Local Filesystem (Dev) / S3 (Prod target)
*   **Deployment:** Docker (Multi-stage build)
