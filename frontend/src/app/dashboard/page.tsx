"use client";

import { useUser, UserButton } from "@clerk/nextjs";
import Link from "next/link";
import { Shield, ArrowRight, LayoutDashboard, User } from "lucide-react";

export default function DashboardWelcome() {
    const { user, isLoaded } = useUser();

    if (!isLoaded) {
        return <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
        </div>;
    }

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col">
            {/* Header */}
            <header className="bg-white dark:bg-gray-800 shadow-sm">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
                    <div className="flex items-center">
                        <Shield className="h-8 w-8 text-indigo-600" />
                        <span className="ml-2 text-xl font-bold text-gray-900 dark:text-white">
                            Remediation Intelligence
                        </span>
                    </div>
                    <div>
                        <UserButton afterSignOutUrl="/" />
                    </div>
                </div>
            </header>

            {/* Main Content */}
            <main className="flex-grow flex items-center justify-center p-6">
                <div className="max-w-4xl w-full text-center space-y-12">

                    {/* Welcome Message */}
                    <div className="space-y-4">
                        <h1 className="text-4xl md:text-5xl font-extrabold text-gray-900 dark:text-white tracking-tight">
                            Welcome back, <span className="text-indigo-600">{user?.firstName || "Defender"}</span>.
                        </h1>
                        <p className="text-xl text-gray-500 dark:text-gray-400 max-w-2xl mx-auto">
                            Your security posture is ready for review.
                            Manage your scans, analyze vulnerabilities, and deploy AI-generated fixes.
                        </p>
                    </div>

                    {/* Action Cards */}
                    <div className="flex justify-center">
                        <Link href="/dashboard/scans"
                            className="group relative p-8 bg-white dark:bg-gray-800 rounded-2xl shadow-xl border border-gray-100 dark:border-gray-700 hover:border-indigo-500 transition-all duration-300 transform hover:-translate-y-1 w-full max-w-lg">
                            <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                                <LayoutDashboard className="h-24 w-24 text-indigo-600" />
                            </div>
                            <div className="text-left space-y-4">
                                <div className="h-12 w-12 bg-indigo-100 dark:bg-indigo-900/30 rounded-lg flex items-center justify-center">
                                    <LayoutDashboard className="h-6 w-6 text-indigo-600" />
                                </div>
                                <h3 className="text-2xl font-bold text-gray-900 dark:text-white">Go to Dashboard</h3>
                                <p className="text-gray-500 dark:text-gray-400">
                                    View your active scans, remediation history, and vulnerability reports.
                                </p>
                                <div className="flex items-center text-indigo-600 font-medium pt-2 group-hover:px-2 transition-all">
                                    Launch Interface <ArrowRight className="ml-2 h-4 w-4" />
                                </div>
                            </div>
                        </Link>
                    </div>
                </div>
            </main>
        </div>
    );
}
