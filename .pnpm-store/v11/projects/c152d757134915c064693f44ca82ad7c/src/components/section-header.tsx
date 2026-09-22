import { LiveStatus } from "./live-status";

export function SectionHeader({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return <header className="page-header"><div><p className="kicker">{eyebrow}</p><h1>{title}</h1><p>{description}</p></div><div className="desktop-status"><LiveStatus /></div></header>;
}

