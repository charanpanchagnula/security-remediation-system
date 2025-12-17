"use client";

import { useEffect, useState } from "react";
import { UserButton, useUser } from "@clerk/nextjs";
import Link from "next/link";
import { Plus, Trash2, Shield, RefreshCw } from "lucide-react";
import { scanApi, ScanSummary } from "@/services/api";

export default function Dashboard() {
    const { user } = useUser();
    const [scans, setScans] = useState<ScanSummary[]>([]);
    const [loading, setLoading] = useState(true);

    const fetchScans = async () => {
        try {
            const data = await scanApi.getAllScans();
            setScans(data);
        } catch (error) {
            console.error("Failed to fetch scans", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchScans();
    }, []);

    const handleDelete = async (scanId: string) => {
        if (!confirm("Are you sure you want to delete this scan?")) return;
        try {
            await scanApi.deleteScan(scanId);
            setScans(scans.filter(s => s.scan_id !== scanId));
        } catch (error) {
            console.error("Failed to delete scan", error);
            alert("Failed to delete scan");
        }
    };

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
            <nav className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between h-16">
                        <Link href="/dashboard" className="flex items-center">
                            <Shield className="h-8 w-8 text-indigo-600" />
                            <span className="ml-2 text-xl font-bold text-gray-900 dark:text-white">
                                Remediation Intelligence
                            </span>
                        </Link>
                        <div className="flex items-center">
                            <div className="mr-4 text-sm text-gray-500 dark:text-gray-300">
                                Welcome, {user?.firstName}
                            </div>
                            <UserButton afterSignOutUrl="/" />
                        </div>
                    </div>
                </div>
            </nav>

            <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
                <div className="px-4 py-6 sm:px-0">
                    <div className="flex justify-between items-center mb-6">
                        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Scan History</h1>
                        <div className="flex space-x-2">
                            <button
                                onClick={() => {
                                    setLoading(true); // Show loading state
                                    fetchScans();
                                }}
                                disabled={loading}
                                className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none disabled:opacity-50"
                            >
                                <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                                {loading ? 'Refreshing...' : 'Refresh'}
                            </button>
                            <Link
                                href="/dashboard/scan/new"
                                className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none"
                            >
                                <Plus className="h-4 w-4 mr-2" />
                                New Scan
                            </Link>
                        </div>
                    </div>

                    <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-md">
                        {loading ? (
                            <div className="p-4 text-center text-gray-500">Loading scans...</div>
                        ) : scans.length === 0 ? (
                            <div className="p-12 text-center text-gray-500">
                                No scans found. Start a new security scan!
                            </div>
                        ) : (
                            <ul className="divide-y divide-gray-200 dark:divide-gray-700">
                                {scans.map((scan) => (
                                    <li key={scan.scan_id}>
                                        <div className="px-4 py-4 flex items-center sm:px-6">
                                            <div className="min-w-0 flex-1 sm:flex sm:items-center sm:justify-between">
                                                <div className="truncate">
                                                    <div className="flex text-sm">
                                                        <p className="font-medium text-indigo-600 truncate">{scan.repo_url}</p>
                                                        <p className="ml-1 flex-shrink-0 font-normal text-gray-500">
                                                            / {scan.scan_id.slice(0, 8)}
                                                        </p>
                                                        <span className={`ml-2 px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${scan.status === "completed" ? "bg-green-100 text-green-800" :
                                                            scan.status === "queued" ? "bg-yellow-100 text-yellow-800" :
                                                                scan.status === "in_progress" ? "bg-blue-100 text-blue-800" :
                                                                    "bg-gray-100 text-gray-800"
                                                            }`}>
                                                            {scan.status}
                                                        </span>
                                                    </div>
                                                    <div className="mt-2 flex">
                                                        <div className="flex items-center text-sm text-gray-500">
                                                            <p>
                                                                {new Date(scan.timestamp).toLocaleString()}
                                                            </p>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div className="mt-4 flex-shrink-0 sm:mt-0 sm:ml-5">
                                                    <div className="flex -space-x-1 overflow-hidden">
                                                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                                            {scan.vuln_count} Vulns
                                                        </span>
                                                        <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                                            {scan.rem_count} Fixes
                                                        </span>
                                                    </div>
                                                </div>
                                            </div>
                                            <div className="ml-5 flex-shrink-0 flex items-center space-x-4">
                                                <Link
                                                    href={`/dashboard/scan/${scan.scan_id}`}
                                                    className="text-indigo-600 hover:text-indigo-900 font-medium text-sm"
                                                >
                                                    View Details
                                                </Link>
                                                <button
                                                    onClick={() => handleDelete(scan.scan_id)}
                                                    className="text-gray-400 hover:text-red-600"
                                                >
                                                    <Trash2 className="h-5 w-5" />
                                                </button>
                                            </div>
                                        </div>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>
                </div>
            </main>
        </div>
    );
}
