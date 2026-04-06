import "./globals.css";

export const metadata = {
    title: "riskybisky portal",
    description: "Container SBOM, vulnerability, and ATT&CK portal",
};

export default function RootLayout({ children }) {
    return (
        <html lang="en">
            <body>{children}</body>
        </html>
    );
}
