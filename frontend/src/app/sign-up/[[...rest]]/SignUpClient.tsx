"use client";
import { SignUp } from "@clerk/clerk-react";

export default function SignUpClient() {
    return (
        <div className="flex items-center justify-center min-h-screen bg-gray-900">
            <SignUp />
        </div>
    );
}
