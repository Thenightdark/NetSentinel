"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/", label: "Overview", mark: "OV" },
  { href: "/traffic", label: "Traffic", mark: "TR" },
  { href: "/hosts", label: "Hosts", mark: "HO" },
  { href: "/alerts", label: "Alerts", mark: "AL" },
];

export function Sidebar() {
  const pathname = usePathname();
  return (
    <aside className="sidebar">
      <Link href="/" className="brand" aria-label="NetSentinel overview">
        <span className="brand-mark" aria-hidden="true"><i /></span>
        <span><strong>NetSentinel</strong><small>Network defense</small></span>
      </Link>
      <nav className="nav" aria-label="Primary navigation">
        {links.map((link) => {
          const active = pathname === link.href;
          return (
            <Link key={link.href} href={link.href} className={active ? "nav-link is-active" : "nav-link"} aria-current={active ? "page" : undefined}>
              <span className="nav-mark" aria-hidden="true">{link.mark}</span>
              <span>{link.label}</span>
            </Link>
          );
        })}
      </nav>
      <div className="sidebar-foot"><span className="status-dot" />Passive monitoring</div>
    </aside>
  );
}

