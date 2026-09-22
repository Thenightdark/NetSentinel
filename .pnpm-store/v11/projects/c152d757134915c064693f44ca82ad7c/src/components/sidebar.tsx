"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { AuthUser, getCurrentUser, logout } from "@/lib/api";

const links = [
  { href: "/", label: "Overview", mark: "OV" },
  { href: "/traffic", label: "Traffic", mark: "TR" },
  { href: "/map", label: "Map", mark: "MP" },
  { href: "/hosts", label: "Hosts", mark: "HO" },
  { href: "/alerts", label: "Alerts", mark: "AL" },
  { href: "/events", label: "Events", mark: "EV" },
  { href: "/agents", label: "Agents", mark: "AG" },
  { href: "/settings", label: "Settings", mark: "ST" },
];

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<AuthUser | null>(null);
  const [signingOut, setSigningOut] = useState(false);

  useEffect(() => {
    getCurrentUser().then(setUser).catch(() => setUser(null));
  }, []);

  async function signOut() {
    setSigningOut(true);
    try {
      await logout();
    } finally {
      router.replace("/login");
      router.refresh();
    }
  }
  return (
    <aside className="sidebar">
      <Link href="/" className="brand" aria-label="NetSentinel overview">
        <span className="brand-mark" aria-hidden="true"><i /></span>
        <span><strong>NetSentinel</strong><small>Network defense</small></span>
      </Link>
      <nav className="nav" aria-label="Primary navigation">
        {links.map((link) => {
          const active = link.href === "/"
            ? pathname === "/"
            : pathname === link.href || pathname.startsWith(`${link.href}/`);
          return (
            <Link key={link.href} href={link.href} className={active ? "nav-link is-active" : "nav-link"} aria-current={active ? "page" : undefined}>
              <span className="nav-mark" aria-hidden="true">{link.mark}</span>
              <span>{link.label}</span>
            </Link>
          );
        })}
      </nav>
      <div className="sidebar-account">
        <div><strong>{user?.username ?? "Signed in"}</strong><small>{user?.role ?? "dashboard user"}</small></div>
        <button onClick={signOut} disabled={signingOut} type="button">{signingOut ? "…" : "Logout"}</button>
      </div>
      <div className="sidebar-foot"><span className="status-dot" />Passive monitoring</div>
    </aside>
  );
}
