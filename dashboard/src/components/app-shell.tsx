"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import { Sidebar } from "@/components/sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    const redirectToLogin = (event: Event) => {
      const returnTo = (event as CustomEvent<string>).detail || "/";
      router.replace(`/login?returnTo=${encodeURIComponent(returnTo)}`);
    };
    window.addEventListener("netsentinel:unauthorized", redirectToLogin);
    return () => window.removeEventListener("netsentinel:unauthorized", redirectToLogin);
  }, [router]);

  if (pathname === "/login") return <>{children}</>;

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="workspace">
        <div className="mobile-bar"><span className="mobile-brand">NetSentinel</span></div>
        <main className="page">{children}</main>
      </div>
    </div>
  );
}
