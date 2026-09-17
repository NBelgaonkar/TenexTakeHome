const ranks: Record<string, string> = {
  high: "border-alert-high/40 bg-alert-high/15 text-alert-high",
  medium: "border-alert-medium/40 bg-alert-medium/15 text-alert-medium",
  low: "border-alert-low/40 bg-alert-low/15 text-alert-low",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = ranks[severity] ?? ranks.medium;
  return (
    <span
      className={`inline-flex rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${cls}`}
    >
      {severity}
    </span>
  );
}
