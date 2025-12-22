import axios from 'axios';

const API_URL = '/api/v1';

const api = axios.create({
  baseURL: API_URL,
});

export interface ScanSummary {
  scan_id: string;
  repo_url: string;
  branch?: string;
  commit_sha?: string;
  timestamp: string;
  vuln_count: number;
  rem_count: number;
  status: string;
}



export interface ScanDetail {
  scan_id: string;
  repo_url: string;
  branch?: string;
  commit_sha?: string;
  timestamp: string;
  status?: string;
  vulnerabilities?: Vulnerability[];
  remediations?: Remediation[];
}

export interface Vulnerability {
  id: string;
  rule_id: string;
  message: string;
  severity: string;
  scanner: string;
  file_path: string;
  start_line: number;
  end_line: number;
  code_snippet: string;
  surrounding_context: string;
  taint_trace?: {
    file_path: string;
    line_number: number;
    code_snippet: string;
    step_description: string;
  }[];
}

export interface CodeChange {
  file_path: string;
  original_code: string;
  new_code: string;
}

export interface Remediation {
  vulnerability_id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  summary: string;
  explanation: string;
  code_changes: CodeChange[];
  security_implications: string[];
  is_false_positive?: boolean;
  confidence_score?: number;
  code_diff?: string; // Legacy support
}



export const scanApi = {
  triggerScan: async (repoUrl: string, branch?: string, scanners: string[] = ['semgrep']) => {
    const payload = {
      repo_url: repoUrl,
      commit_sha: branch,
      scanner_types: scanners
    };
    const response = await api.post('/scan', payload);
    return response.data;
  },

  getAllScans: async (): Promise<ScanSummary[]> => {
    const response = await api.get('/scans');
    return response.data;
  },

  getScan: async (scanId: string): Promise<ScanDetail> => {
    const response = await api.get(`/scans/${scanId}`);
    return response.data;
  },

  async deleteScan(scanId: string): Promise<void> {
    const response = await axios.delete(`${API_URL}/scans/${scanId}`);
    return response.data;
  },

  async generateRemediation(scanId: string, vulnId: string): Promise<Remediation> {
    const response = await axios.post(`${API_URL}/scan/${scanId}/remediate/${vulnId}`);
    return response.data;
  },

  async generateBatchRemediation(scanId: string): Promise<void> {
    await axios.post(`${API_URL}/scan/${scanId}/remediate-all`);
  }
};
