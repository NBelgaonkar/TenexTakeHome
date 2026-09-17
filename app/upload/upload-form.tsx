"use client";

import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";

export function UploadForm() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<"idle" | "uploading">("idle");

  const onFile = useCallback((next: File | null) => {
    setFile(next);
    setError(null);
  }, []);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!file) {
      setError("Choose a .log or .txt file.");
      return;
    }
    setPhase("uploading");
    setError(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const res = await fetch("/api/logs/upload", { method: "POST", body });
      const data = (await res.json()) as { error?: string; sessionId?: string };
      if (!res.ok || !data.sessionId) {
        setError(data.error ?? "Upload failed.");
        setPhase("idle");
        return;
      }
      router.push(`/results/${data.sessionId}`);
      router.refresh();
    } catch {
      setError("Network error during upload.");
      setPhase("idle");
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-5">
      <label
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          const dropped = e.dataTransfer.files[0];
          if (dropped) onFile(dropped);
        }}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed px-6 py-14 transition ${
          dragOver
            ? "border-signal bg-signal/10"
            : "border-line bg-ink-950/60 hover:border-signal/40"
        }`}
      >
        <input
          type="file"
          accept=".log,.txt,text/plain"
          className="hidden"
          onChange={(e) => onFile(e.target.files?.[0] ?? null)}
        />
        <p className="text-sm font-medium">Drop a ZScaler NSS log here</p>
        <p className="mt-1 font-mono text-xs text-mist">
          .log or .txt · 10MB cap · text bytes only
        </p>
        {file ? (
          <p className="mt-4 font-mono text-sm text-signal">{file.name}</p>
        ) : null}
      </label>

      {phase === "uploading" ? (
        <p className="text-sm text-signal">
          Uploading, parsing, and running anomaly detection…
        </p>
      ) : null}

      {error ? (
        <p className="rounded-md border border-alert-high/30 bg-alert-high/10 px-3 py-2 text-sm text-alert-high">
          {error}
        </p>
      ) : null}

      <button className="btn-primary" type="submit" disabled={phase !== "idle"}>
        {phase === "uploading" ? "Processing…" : "Analyze log"}
      </button>
    </form>
  );
}
