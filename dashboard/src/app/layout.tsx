import type { Metadata } from "next";
import { Sidebar } from "@/components/sidebar";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "NetSentinel", template: "%s · NetSentinel" },
  description: "Defensive network observability dashboard",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><div className="app-shell"><Sidebar /><div className="workspace"><div className="mobile-bar"><span className="mobile-brand">NetSentinel</span></div><main className="page">{children}</main></div></div></body></html>;
}
