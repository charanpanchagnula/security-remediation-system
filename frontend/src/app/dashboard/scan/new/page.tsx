"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { scanApi } from "@/services/api";
import Link from "next/link";
import { ArrowLeft, Loader2 } from "lucide-react";

export default function NewScanPage() {
    const router = useRouter();
    const [repoUrl, setRepoUrl] = useState("");
    const [branch, setBranch] = useState("");
    const [scanners, setScanners] = useState(["semgrep"]);
    const [isSubmitting, setIsSubmitting] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            await scanApi.triggerScan(repoUrl, branch || undefined, scanners);
            // Wait a bit or redirect immediately. The backend queues it.
            // Ideally we redirect to the scan details page if we had the ID, 
            // but triggerScan returns {scan_id, status}.
            router.push("/dashboard");
        } catch (error) {
            console.error("Scan failed", error);
            alert("Failed to trigger scan");
        } finally {
            setIsSubmitting(false);
        }
    };

    const toggleScanner = (scanner: string) => {
        if (scanners.includes(scanner)) {
            setScanners(scanners.filter(s => s !== scanner));
        } else {
            setScanners([...scanners, scanner]);
        }
    };

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
            <div className="max-w-md mx-auto bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
                <div className="px-4 py-4 mb-6">
                    <Link href="/dashboard/scans" className="text-indigo-600 hover:text-indigo-900 flex items-center">
                        <ArrowLeft className="h-4 w-4 mr-2" />
                        Back to Scans
                    </Link>
                </div>
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center">
                    <h2 className="text-xl font-semibold text-gray-900 dark:text-white">New Security Scan</h2>
                </div>

                <form onSubmit={handleSubmit} className="p-6 space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                            GitHub Repository URL
                        </label>
                        <input
                            type="text"
                            required
                            placeholder="https://github.com/owner/repo"
                            value={repoUrl}
                            onChange={(e) => setRepoUrl(e.target.value)}
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2 bg-white dark:bg-gray-700 dark:text-white border"
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                            Branch / Commit SHA (Optional)
                        </label>
                        <input
                            type="text"
                            placeholder="main"
                            value={branch}
                            onChange={(e) => setBranch(e.target.value)}
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm p-2 bg-white dark:bg-gray-700 dark:text-white border"
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            Scanners
                        </label>
                        <div className="space-y-2">
                            <label className="flex items-center space-x-3">
                                <input
                                    type="checkbox"
                                    checked={scanners.includes("semgrep")}
                                    onChange={() => toggleScanner("semgrep")}
                                    className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                                />
                                <span className="text-gray-700 dark:text-gray-300">Semgrep (SAST & MCP)</span>
                            </label>
                            <label className="flex items-center space-x-3">
                                <input
                                    type="checkbox"
                                    checked={scanners.includes("checkov")}
                                    onChange={() => toggleScanner("checkov")}
                                    className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                                />
                                <span className="text-gray-700 dark:text-gray-300">Checkov (IaC)</span>
                            </label>
                            <label className="flex items-center space-x-3">
                                <input
                                    type="checkbox"
                                    checked={scanners.includes("trivy")}
                                    onChange={() => toggleScanner("trivy")}
                                    className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                                />
                                <span className="text-gray-700 dark:text-gray-300">Trivy (SCA & Secrets)</span>
                            </label>

                        </div>
                    </div>

                    <div className="pt-4">
                        <button
                            type="submit"
                            disabled={isSubmitting || scanners.length === 0}
                            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                        >
                            {isSubmitting ? (
                                <>
                                    <Loader2 className="animate-spin -ml-1 mr-2 h-4 w-4" />
                                    Starting Scan...
                                </>
                            ) : (
                                "Start Scan"
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
