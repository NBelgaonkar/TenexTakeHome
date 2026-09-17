"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { TimelineBucket } from "@/lib/types";

export function TimelineChart({ data }: { data: TimelineBucket[] }) {
  const rows = data.map((bucket) => ({
    ...bucket,
    label: bucket.hour.slice(11, 16),
    day: bucket.hour.slice(0, 10),
  }));

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="#1e2833" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fill: "#8b9bb0", fontSize: 11, fontFamily: "IBM Plex Mono" }}
            axisLine={{ stroke: "#2a3644" }}
            tickLine={false}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: "#8b9bb0", fontSize: 11, fontFamily: "IBM Plex Mono" }}
            axisLine={false}
            tickLine={false}
            width={36}
          />
          <Tooltip
            cursor={{ fill: "rgba(62, 224, 197, 0.08)" }}
            contentStyle={{
              background: "#121821",
              border: "1px solid #2a3644",
              borderRadius: 8,
              color: "#e8eef4",
              fontSize: 12,
            }}
            labelFormatter={(_, payload) => {
              const row = payload?.[0]?.payload as { day?: string; hour?: string } | undefined;
              return row?.hour ?? "";
            }}
          />
          <Bar dataKey="count" fill="#3ee0c5" radius={[4, 4, 0, 0]} maxBarSize={28} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
