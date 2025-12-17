"use client";

import { useEffect, useState, use } from "react";
import { scanApi, ScanDetail, Vulnerability } from "@/services/api";
import Link from "next/link";
import { ArrowLeft, AlertTriangle, CheckCircle, FileText, ExternalLink, Shield, Loader2, Wand2 } from "lucide-react";

export default function ScanPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const [scan, setScan] = useState<ScanDetail | null>(null);
    const [loading, setLoading] = useState(true);
    const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
    const [generating, setGenerating] = useState<Set<string>>(new Set()); // IDs of vulns being remediated
    const [batchGenerating, setBatchGenerating] = useState(false);
    const [selectedDetailScanner, setSelectedDetailScanner] = useState("All");

    useEffect(() => {
        const fetchScan = async () => {
            try {
                const data = await scanApi.getScan(id);
                setScan(data);
                if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                    setSelectedVuln(data.vulnerabilities[0]);
                }
            } catch (error) {
                console.error("Failed to fetch scan details", error);
            } finally {
                setLoading(false);
            }
        };
        fetchScan();
    }, [id]);

    if (loading) {
        return <div className="p-12 text-center">Loading scan details...</div>;
    }

    if (!scan) {
        return (
            <div className="p-12 text-center text-red-500">
                Scan not found.
                <Link href="/dashboard" className="block mt-4 text-indigo-600 underline">
                    Back to Dashboard
                </Link>
            </div>
        );
    }

    const isProcessing = scan.status === "queued" || scan.status === "in_progress";

    if (isProcessing) {
        return (
            <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto mb-4"></div>
                    <h2 className="text-xl font-bold text-gray-900 dark:text-white">Scan in Progress</h2>
                    <p className="text-gray-500 mt-2">Status: {scan.status}</p>
                    <Link href="/dashboard" className="block mt-4 text-indigo-600 underline">
                        Back to Dashboard
                    </Link>
                </div>
            </div>
        );
    }

    // Remediation JSON correlates via 'vulnerability_id' which matches the 'rule_id' of the vulnerability
    const remediation = selectedVuln ? scan.remediations?.find(r => r.vulnerability_id === selectedVuln.rule_id) : null;

    const handleBatchRemediate = async () => {
        if (!confirm("This will trigger AI remediation for all vulnerabilities. Continue?")) return;
        setBatchGenerating(true);
        try {
            if (!scan) return;
            await scanApi.generateBatchRemediation(scan.scan_id);
            alert("Batch remediation started in background. Refresh explicitly to see progress.");
        } catch (e) {
            console.error(e);
            alert("Failed to start batch remediation");
        } finally {
            setBatchGenerating(false);
        }
    };

    const getSeverityWeight = (severity: string) => {
        const map: Record<string, number> = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0
        };
        return map[severity?.toUpperCase()] || 0;
    };

    const filteredVulns = (scan?.vulnerabilities || [])
        .filter(v => selectedDetailScanner === "All" || v.scanner?.toLowerCase() === selectedDetailScanner.toLowerCase())
        .sort((a, b) => getSeverityWeight(b.severity) - getSeverityWeight(a.severity));

    const getScannerCount = (scannerName: string) => {
        if (scannerName === "All") return (scan?.vulnerabilities || []).length;
        return (scan?.vulnerabilities || []).filter(v => v.scanner?.toLowerCase() === scannerName.toLowerCase()).length;
    };

    const getSeverityColor = (severity: string) => {
        switch (severity?.toUpperCase()) {
            case "CRITICAL": return "bg-red-100 text-red-800 border-red-200";
            case "HIGH": return "bg-orange-100 text-orange-800 border-orange-200";
            case "MEDIUM": return "bg-yellow-100 text-yellow-800 border-yellow-200";
            case "LOW": return "bg-blue-100 text-blue-800 border-blue-200";
            default: return "bg-gray-100 text-gray-800 border-gray-200";
        }
    };

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col">
            <nav className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between h-16">
                        <div className="flex items-center">
                            <Shield className="h-8 w-8 text-indigo-600" />
                            <span className="ml-2 text-xl font-bold text-gray-900 dark:text-white">
                                Remediation Intelligence
                            </span>
                        </div>
                    </div>
                </div>
            </nav>

            <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 flex-grow py-8 overflow-hidden h-[calc(100vh-64px)]">
                <div className="px-4 py-4 mb-6 flex items-center justify-between">
                    <div className="flex items-center">
                        <Link href="/dashboard/scans" className="mr-4 text-gray-500 hover:text-gray-700">
                            <ArrowLeft className="h-6 w-6" />
                        </Link>
                        <div>
                            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Scan Results</h1>
                            <p className="text-sm text-gray-500">{scan.repo_url} (ID: {scan.scan_id.slice(0, 8)})</p>
                        </div>
                    </div>
                    <div className="flex space-x-3">
                        <button
                            onClick={handleBatchRemediate}
                            disabled={batchGenerating}
                            className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none disabled:opacity-50"
                        >
                            {batchGenerating ? (
                                <>
                                    <Loader2 className="animate-spin -ml-1 mr-2 h-4 w-4" />
                                    Generating All Fixes...
                                </>
                            ) : (
                                <>
                                    <Wand2 className="-ml-1 mr-2 h-4 w-4" />
                                    Generate Fix recommendation for all vulnerabilities
                                </>
                            )}
                        </button>
                    </div>
                </div>

                <div className="flex flex-col lg:flex-row gap-6 px-4 h-[calc(100%-100px)]">
                    {/* Sidebar: Vulnerability List */}
                    <div className="w-full lg:w-1/3 bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden flex flex-col h-full border border-gray-200 dark:border-gray-700">
                        <div className="flex border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50">
                            {["All", "Semgrep", "Checkov", "Trivy"].map((scanner) => (
                                <button
                                    key={scanner}
                                    onClick={() => setSelectedDetailScanner(scanner)}
                                    className={`flex-1 py-3 text-sm font-medium border-b-2 transition-colors ${selectedDetailScanner === scanner
                                        ? "border-indigo-600 text-indigo-600 dark:text-indigo-400 bg-white dark:bg-gray-800"
                                        : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                                        }`}
                                >
                                    {scanner} <span className="ml-1 text-xs bg-gray-200 dark:bg-gray-700 px-1.5 py-0.5 rounded-full text-gray-600 dark:text-gray-300">{getScannerCount(scanner)}</span>
                                </button>
                            ))}
                        </div>
                        <div className="flex-1 overflow-y-auto">
                            {filteredVulns.map((vuln) => (
                                <button
                                    key={vuln.id}
                                    onClick={() => setSelectedVuln(vuln)}
                                    className={`w-full text-left p-4 border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors ${selectedVuln?.id === vuln.id ? "bg-indigo-50 dark:bg-indigo-900/20 border-l-4 border-l-indigo-600" : "border-l-4 border-l-transparent"
                                        }`}
                                >
                                    <div className="flex justify-between items-start mb-1">
                                        <span className={`px-2 py-0.5 rounded text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                                            {vuln.severity}
                                        </span>
                                        <span className="text-xs text-gray-400 font-mono capitalize ml-2">{vuln.scanner}</span>
                                    </div>
                                    <p className="font-medium text-gray-900 dark:text-white text-sm line-clamp-2">
                                        {vuln.message}
                                    </p>
                                    <p className="text-xs text-gray-500 mt-1 truncate">
                                        {vuln.file_path}:{vuln.start_line}
                                    </p>
                                    {vuln.remediation && (
                                        <div className="mt-2 flex items-center text-xs text-green-600 font-medium">
                                            <CheckCircle className="h-3 w-3 mr-1" />
                                            Fix Available
                                        </div>
                                    )}
                                </button>
                            ))}
                            {filteredVulns.length === 0 && (
                                <div className="p-8 text-center text-gray-500 text-sm">
                                    No vulnerabilities found for this filter.
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Main Content: Details & Remediation */}
                    <div className="w-full lg:w-2/3 space-y-6 h-full overflow-y-auto pr-2 pb-20">
                        {selectedVuln ? (
                            <>
                                {/* Vulnerability Details */}
                                <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
                                    <div className="flex justify-between items-start mb-4">
                                        <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                            Vulnerability Details
                                        </h3>
                                        {scan.repo_url && (
                                            <a
                                                href={`${scan.repo_url.replace(/\/$/, "")}/blob/HEAD/${selectedVuln.file_path.replace(/^\//, "")}#L${selectedVuln.start_line}-L${selectedVuln.end_line}`}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 flex items-center"
                                            >
                                                <span className="mr-1">View on GitHub</span>
                                                <ExternalLink className="h-4 w-4" />
                                            </a>
                                        )}
                                    </div>
                                    <pre className="bg-gray-50 dark:bg-gray-900 rounded-md p-4 mb-4 font-mono text-sm overflow-x-auto text-gray-800 dark:text-gray-200 whitespace-pre-wrap border border-gray-200 dark:border-gray-700">
                                        <code>{selectedVuln.surrounding_context || selectedVuln.code_snippet}</code>
                                    </pre>
                                    <div className="grid grid-cols-2 gap-4 text-sm text-gray-500">
                                        <div>
                                            <span className="font-medium">Rule ID:</span> {selectedVuln.rule_id}
                                        </div>
                                        <div>
                                            <span className="font-medium">Severity:</span> {selectedVuln.severity}
                                        </div>
                                    </div>
                                </div>

                                {/* Remediation Section */}
                                {remediation ? (
                                    <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6 border-t-4 border-green-500">
                                        <div className="flex items-center mb-4 space-x-2">
                                            {remediation.is_false_positive ? (
                                                <div className="flex items-center text-gray-500 bg-gray-100 dark:bg-gray-700 px-3 py-1 rounded-full">
                                                    <Shield className="h-5 w-5 mr-2" />
                                                    <h3 className="text-lg font-medium">False Positive</h3>
                                                </div>
                                            ) : (
                                                <div className="flex items-center">
                                                    <CheckCircle className="h-6 w-6 text-green-500 mr-2" />
                                                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                                        AI Remediation Plan
                                                    </h3>
                                                </div>
                                            )}

                                            {remediation.confidence_score !== undefined && (
                                                <span className={`px-2 py-1 text-xs font-bold rounded-full ${remediation.confidence_score > 0.8 ? "bg-green-100 text-green-800" : "bg-yellow-100 text-yellow-800"
                                                    }`}>
                                                    Confidence: {(remediation.confidence_score * 100).toFixed(0)}%
                                                </span>
                                            )}
                                        </div>

                                        <div className="prose dark:prose-invert max-w-none">
                                            <p className="text-gray-600 dark:text-gray-300 mb-4">
                                                {remediation.summary}
                                            </p>

                                            <div className="bg-gray-900 rounded-md p-4 text-white overflow-x-auto mb-4">
                                                <h4 className="text-xs font-bold uppercase text-gray-400 mb-2">Code Fix</h4>
                                                {remediation.code_changes?.map((change, idx) => (
                                                    <div key={idx} className="mb-4">
                                                        <div className="flex items-center justify-between mb-1">
                                                            <p className="text-xs text-gray-500 font-mono">{change.file_path}</p>
                                                            {scan.repo_url && (
                                                                <a
                                                                    href={`${scan.repo_url.replace(/\/$/, "")}/blob/HEAD/${change.file_path.replace(/^\//, "")}`}
                                                                    target="_blank"
                                                                    rel="noopener noreferrer"
                                                                    className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center"
                                                                >
                                                                    <span className="mr-1">View File</span>
                                                                    <ExternalLink className="h-3 w-3" />
                                                                </a>
                                                            )}
                                                        </div>
                                                        <pre className="text-sm p-2 bg-gray-800 rounded border border-gray-700"><code>{change.new_code}</code></pre>
                                                    </div>
                                                ))}
                                                {/* Fallback if code_diff was used previously */}
                                                {remediation.code_diff && <pre className="text-sm"><code>{remediation.code_diff}</code></pre>}
                                            </div>

                                            <div className="bg-blue-50 dark:bg-blue-900/20 rounded-md p-4">
                                                <h4 className="text-sm font-bold text-blue-800 dark:text-blue-300 mb-1">Explanation</h4>
                                                <div className="text-sm text-blue-700 dark:text-blue-200 whitespace-pre-wrap">
                                                    {remediation.explanation}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6 text-center text-gray-500">
                                        <FileText className="h-12 w-12 mx-auto text-gray-300 mb-2" />
                                        <p className="mb-4">No remediation generated for this vulnerability yet.</p>

                                        <button
                                            onClick={async () => {
                                                if (!selectedVuln || generating.has(selectedVuln.id)) return;
                                                setGenerating(new Set(generating).add(selectedVuln.id));
                                                try {
                                                    const rem = await scanApi.generateRemediation(scan.scan_id, selectedVuln.id);
                                                    // Update local state immediately
                                                    const updatedScan = { ...scan };
                                                    if (!updatedScan.remediations) updatedScan.remediations = [];
                                                    updatedScan.remediations.push(rem);
                                                    setScan(updatedScan);
                                                } catch (e) {
                                                    console.error(e);
                                                    alert("Failed to generate remediation");
                                                } finally {
                                                    const newSet = new Set(generating);
                                                    newSet.delete(selectedVuln.id);
                                                    setGenerating(newSet);
                                                }
                                            }}
                                            disabled={generating.has(selectedVuln.id)}
                                            className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700"
                                        >
                                            {generating.has(selectedVuln.id) ? (
                                                <>
                                                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                                                    Generating AI Fix...
                                                </>
                                            ) : (
                                                "Generate AI Remediation"
                                            )}
                                        </button>
                                    </div>
                                )}
                            </>
                        ) : (
                            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-12 text-center text-gray-500">
                                Select a vulnerability to view details.
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div >
    );
}
