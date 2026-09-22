export function MetricCard({ label, value, detail, tone = "cyan" }: { label: string; value: string; detail: string; tone?: "cyan" | "lime" | "amber" | "blue" }) {
  return <article className={`metric-card metric-card--${tone}`}><div className="metric-top"><span>{label}</span><i aria-hidden="true" /></div><strong>{value}</strong><small>{detail}</small></article>;
}

