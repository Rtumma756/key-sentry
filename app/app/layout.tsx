import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "KeySentry — AI API Leaked-Key Scanner",
  description:
    "Paste code, find leaked AI API keys, fix them. Everything runs in your browser — pasted code never leaves your machine.",
};

export default function AppLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
