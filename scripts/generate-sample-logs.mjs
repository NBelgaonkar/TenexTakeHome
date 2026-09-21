import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(__dirname, "../sample-logs");

const IPS = ["10.20.30.10", "10.20.30.11", "10.20.30.12", "10.20.30.13"];
const USERS = [
  "alice@corp.com",
  "bob@corp.com",
  "carol@corp.com",
  "dave@corp.com",
];
const URLS = [
  "https://www.office.com/",
  "https://github.com/",
  "https://www.google.com/search",
  "https://corp.slack.com/messages",
  "https://login.microsoftonline.com/",
  "https://stackoverflow.com/questions",
  "https://www.linkedin.com/feed",
  "https://corp.atlassian.net/jira",
];
const UAS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
];

function pad(n) {
  return String(n).padStart(2, "0");
}

function nssTime(date) {
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const months = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
  ];
  return `${days[date.getUTCDay()]} ${months[date.getUTCMonth()]} ${date.getUTCDate()} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} ${date.getUTCFullYear()}`;
}

function line({ date, ip, user, url, action, sent, recv, ua }) {
  return [
    nssTime(date),
    "GMT",
    ip,
    user,
    url,
    action,
    String(sent),
    String(recv),
    ua,
  ].join("\t");
}

function normalLines() {
  const start = Date.UTC(2024, 2, 11, 13, 0, 0);
  const intervalMs = 160 * 1000;
  const lines = [];
  for (let i = 0; i < 180; i += 1) {
    const date = new Date(start + i * intervalMs);
    const ip = IPS[i % IPS.length];
    const user = USERS[i % USERS.length];
    const url = URLS[i % URLS.length];
    const action = i % 17 === 0 ? "Blocked" : "Allowed";
    const sent = 800 + (i % 40) * 90;
    const recv = 1200 + (i % 55) * 180;
    const ua = UAS[i % UAS.length];
    lines.push(line({ date, ip, user, url, action, sent, recv, ua }));
  }
  return lines;
}

function anomalousLines() {
  const lines = normalLines();
  const ua = UAS[0];

  // Original burst: 25 requests in 25s from 10.9.9.9 → office.com at 16:00 GMT (noon EDT).
  for (let i = 0; i < 25; i += 1) {
    const date = new Date(Date.UTC(2024, 2, 11, 16, 0, i));
    lines.push(
      line({
        date,
        ip: "10.9.9.9",
        user: "eve@corp.com",
        url: "https://www.office.com/",
        action: "Allowed",
        sent: 900,
        recv: 1800,
        ua,
      }),
    );
  }

  // Second burst: 28 requests, 2s apart (~54s window) from a different IP, late
  // afternoon, to Salesforce — distinct incident from the office.com noon burst.
  for (let i = 0; i < 28; i += 1) {
    const date = new Date(Date.UTC(2024, 2, 11, 20, 10, i * 2));
    lines.push(
      line({
        date,
        ip: "10.4.4.20",
        user: "frank@corp.com",
        url: "https://login.salesforce.com/",
        action: "Allowed",
        sent: 640,
        recv: 1100,
        ua,
      }),
    );
  }

  // Original off-hours: Tue 07:10 GMT = 03:10 EDT, before 08:00 business start.
  for (let i = 0; i < 4; i += 1) {
    const date = new Date(Date.UTC(2024, 2, 12, 7, 10, i * 15));
    lines.push(
      line({
        date,
        ip: "10.20.30.10",
        user: "alice@corp.com",
        url: "https://github.com/",
        action: "Allowed",
        sent: 1100,
        recv: 2400,
        ua,
      }),
    );
  }

  // Original large transfer: ~50MB Office export (above the 5MB floor).
  lines.push(
    line({
      date: new Date(Date.UTC(2024, 2, 11, 18, 30, 0)),
      ip: "10.20.30.12",
      user: "carol@corp.com",
      url: "https://www.office.com/share/export",
      action: "Allowed",
      sent: 4096,
      recv: 52_428_800,
      ua,
    }),
  );

  // Zoom heartbeats so zoom.us is not a first-seen / rare_domain hit.
  for (const minute of [12, 28, 51]) {
    lines.push(
      line({
        date: new Date(Date.UTC(2024, 2, 11, 15, minute, 0)),
        ip: "10.20.30.10",
        user: "alice@corp.com",
        url: "https://zoom.us/j/heartbeat",
        action: "Allowed",
        sent: 900,
        recv: 2400,
        ua,
      }),
    );
  }

  // FALSE-POSITIVE large_transfer: ~4.2MB Zoom recording from a normal IP during
  // business hours. Session median is ~10KB so max(10×median, 5MB) = 5MB; this
  // row is deliberately under that floor (a 15–20MB download would be flagged).
  lines.push(
    "# FALSE-POSITIVE large_transfer: Zoom recording 10.20.30.10 → zoom.us ~4.2MB at 15:40 GMT. Below max(10x session median, 5MB)=5MB; must stay unflagged.",
  );
  lines.push(
    line({
      date: new Date(Date.UTC(2024, 2, 11, 15, 40, 0)),
      ip: "10.20.30.10",
      user: "alice@corp.com",
      url: "https://zoom.us/recording/download",
      action: "Allowed",
      sent: 120_000,
      recv: 4_194_304,
      ua,
    }),
  );

  // Original rare / denylisted TLD: .xyz
  lines.push(
    line({
      date: new Date(Date.UTC(2024, 2, 11, 19, 5, 0)),
      ip: "10.20.30.11",
      user: "bob@corp.com",
      url: "https://steal-session.xyz/login",
      action: "Allowed",
      sent: 512,
      recv: 2048,
      ua,
    }),
  );

  // Additional rare_domain: first-seen vendor portal (legitimate TLD, appears once).
  lines.push(
    line({
      date: new Date(Date.UTC(2024, 2, 11, 17, 12, 0)),
      ip: "10.20.30.13",
      user: "dave@corp.com",
      url: "https://portal.docusign.net/signing",
      action: "Allowed",
      sent: 1400,
      recv: 3200,
      ua,
    }),
  );

  // Additional rare_domain: another first-seen but plausible corporate destination.
  lines.push(
    line({
      date: new Date(Date.UTC(2024, 2, 11, 17, 48, 0)),
      ip: "10.20.30.11",
      user: "bob@corp.com",
      url: "https://status.pagerduty.com/",
      action: "Allowed",
      sent: 780,
      recv: 2100,
      ua,
    }),
  );

  // Additional rare_domain: denylisted TLD other than .xyz (proves the list isn't a single-case check).
  lines.push(
    line({
      date: new Date(Date.UTC(2024, 2, 11, 19, 22, 0)),
      ip: "10.20.30.12",
      user: "carol@corp.com",
      url: "https://payload-cdn.click/beacon",
      action: "Allowed",
      sent: 384,
      recv: 1536,
      ua,
    }),
  );

  return lines;
}

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "normal.log"), `${normalLines().join("\n")}\n`);
fs.writeFileSync(
  path.join(outDir, "anomalous.log"),
  `${anomalousLines().join("\n")}\n`,
);
console.log("Wrote sample-logs/normal.log and sample-logs/anomalous.log");
