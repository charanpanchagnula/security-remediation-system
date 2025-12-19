"use client";
import { ClerkProvider } from "@clerk/clerk-react";

export function Providers({ children }: { children: React.ReactNode }) {
    const publishableKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
    console.log("Clerk Publishable Key:", publishableKey);

    if (!publishableKey) {
        console.warn("Missing Clerk Publishable Key");
    }

    return (
        <ClerkProvider publishableKey={publishableKey || ""} afterSignOutUrl="/">
            {children}
        </ClerkProvider>
    );
}
