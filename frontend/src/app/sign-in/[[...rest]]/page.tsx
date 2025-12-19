import SignInClient from "./SignInClient";

export function generateStaticParams() {
    return [{ rest: [] }];
}

export default function Page() {
    return <SignInClient />;
}
