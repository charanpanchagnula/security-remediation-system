import SignUpClient from "./SignUpClient";

export function generateStaticParams() {
    return [{ rest: [] }];
}

export default function Page() {
    return <SignUpClient />;
}
