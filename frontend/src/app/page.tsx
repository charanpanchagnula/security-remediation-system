"use client";
import Link from "next/link";
import { Shield, Check, Lock, Cpu, ArrowRight } from "lucide-react";
import { useUser } from "@clerk/clerk-react";

export default function LandingPage() {
  const { isSignedIn } = useUser();
  return (
    <div className="min-h-screen bg-white dark:bg-slate-900 selection:bg-indigo-500 selection:text-white font-sans">

      {/* Navigation */}
      <nav className="fixed w-full z-50 bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="h-8 w-8 text-indigo-600" />
            <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-600 to-violet-600 dark:from-indigo-400 dark:to-violet-400">
              Remediation Intelligence
            </span>
          </div>
          <div className="hidden md:flex items-center space-x-8">
            <a href="#features" className="text-sm font-medium text-slate-600 dark:text-slate-300 hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors">Features</a>
            {isSignedIn ? (
              <Link href="/dashboard" className="px-5 py-2.5 rounded-full bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold transition-all shadow-lg shadow-indigo-500/30 hover:shadow-indigo-500/50">
                Go to Dashboard
              </Link>
            ) : (
              <Link href="/dashboard" className="px-5 py-2.5 rounded-full bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold transition-all shadow-lg shadow-indigo-500/30 hover:shadow-indigo-500/50">
                Sign In
              </Link>
            )}
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 lg:pt-48 lg:pb-32 overflow-hidden">
        <div className="absolute inset-0 -z-10 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-indigo-100 via-slate-50 to-white dark:from-slate-800 dark:via-slate-900 dark:to-slate-950 opacity-70"></div>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-5xl md:text-7xl font-extrabold text-slate-900 dark:text-white tracking-tight mb-8">
            Secure your code <br className="hidden md:block" />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-600 to-violet-600 dark:from-indigo-400 dark:to-violet-400">
              Fix it automatically.
            </span>
          </h1>
          <p className="mt-6 max-w-2xl mx-auto text-lg md:text-xl text-slate-600 dark:text-slate-400 leading-relaxed">
            The first security platform that doesn't just find bugs—it fixes them.
            Combine Semgrep, Checkov, and Trivy with advanced AI to auto-remediate vulnerabilities in seconds.
          </p>
          <div className="mt-10 flex flex-col sm:flex-row justify-center gap-4">
            <Link href="/dashboard" className="inline-flex items-center justify-center px-8 py-4 text-base font-bold text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 transition-all shadow-xl shadow-indigo-600/20 hover:shadow-indigo-600/40">
              Start Securing Now
              <ArrowRight className="ml-2 h-5 w-5" />
            </Link>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section id="features" className="py-24 bg-slate-50 dark:bg-slate-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white">Enterprise-Grade Security Pipeline</h2>
            <p className="mt-4 text-slate-600 dark:text-slate-400">Everything you need to ship secure code, out of the box.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                icon: <Cpu className="h-6 w-6 text-indigo-100" />,
                title: "Multi-Engine Scanning",
                desc: "Unified results from Semgrep (SAST), Checkov (IaC), and Trivy (SCA & Secrets) in one view."
              },
              {
                icon: <Lock className="h-6 w-6 text-indigo-100" />,
                title: "AI Auto-Remediation",
                desc: "Don't just stare at logs. Click 'Remediate' and let our AI generate production-ready code fixes."
              },
              {
                icon: <Shield className="h-6 w-6 text-indigo-100" />,
                title: "Zero Setup",
                desc: "Connect your repo URL and start scanning immediately. No complex CI/CD configuration required."
              }
            ].map((feature, idx) => (
              <div key={idx} className="bg-white dark:bg-slate-800 p-8 rounded-2xl shadow-sm hover:shadow-md transition-shadow border border-slate-100 dark:border-slate-700">
                <div className="h-12 w-12 bg-indigo-600 rounded-xl flex items-center justify-center mb-6 shadow-lg shadow-indigo-600/30">
                  {feature.icon}
                </div>
                <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-3">{feature.title}</h3>
                <p className="text-slate-600 dark:text-slate-400 leading-relaxed">{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-white dark:bg-slate-950 py-12 border-t border-slate-200 dark:border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center">
          <div className="flex items-center space-x-2 mb-4 md:mb-0">
            <Shield className="h-6 w-6 text-indigo-600" />
            <span className="font-bold text-slate-900 dark:text-white">Remediation Intelligence</span>
          </div>
          <div className="text-sm text-slate-500">
            © 2024 AI Security Remediation. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}
