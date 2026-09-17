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

  return lines;
}

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "normal.log"), `${normalLines().join("\n")}\n`);
fs.writeFileSync(
  path.join(outDir, "anomalous.log"),
  `${anomalousLines().join("\n")}\n`,
);
console.log("Wrote sample-logs/normal.log and sample-logs/anomalous.log");
