import { Suspense } from "react";
import ScanClient from "./ScanClient";

export default function ScanPage() {
    return (
        <Suspense fallback={<div>Loading...</div>}>
            <ScanClient />
        </Suspense>
    );
}
