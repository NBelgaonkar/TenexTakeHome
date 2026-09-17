import type { AnomalyRule } from "@/lib/types";

export function ruleLabel(rule: AnomalyRule): string {
  switch (rule) {
    case "high_request_rate":
      return "High request rate";
    case "off_hours":
      return "Off-hours access";
    case "large_transfer":
      return "Large transfer";
    case "rare_domain":
      return "Rare / suspicious domain";
  }
}
