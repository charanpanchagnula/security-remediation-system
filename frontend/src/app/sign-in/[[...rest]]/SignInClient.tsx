"use client";

import { SignIn } from "@clerk/clerk-react";

export default function SignInClient() {
    return (
        <div className="flex items-center justify-center min-h-screen bg-gray-900">
            <SignIn />
        </div>
    );
}
