"use client";

import { useEffect, useState } from "react";
import { readShell, fetchShells } from "@/lib/gateway";

export default function ShellView({ params }: { params: Promise<{ id: string }> }) {
  const [engagementId, setEngagementId] = useState<string>("");
  const [sessions, setSessions] = useState<any[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [output, setOutput] = useState<string>("");

  useEffect(() => {
    params.then((p) => setEngagementId(p.id));
  }, [params]);

  useEffect(() => {
    if (!engagementId) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const data = await fetchShells(engagementId);
        if (!cancelled) {
          setSessions(data.sessions);
          if (!selected && data.sessions.length) setSelected(data.sessions[0].name);
        }
      } catch {
        /* gateway down */
      }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [engagementId, selected]);

  useEffect(() => {
    if (!engagementId || !selected) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const data = await readShell(engagementId, selected);
        if (!cancelled) setOutput(data.output || "");
      } catch {
        /* */
      }
    };
    poll();
    const id = setInterval(poll, 1500);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [engagementId, selected]);

  return (
    <div>
      <h2>Shell view ({engagementId.slice(0, 8)})</h2>
      <div style={{ display: "flex", gap: 16 }}>
        <ul style={{ minWidth: 200, listStyle: "none", padding: 0 }}>
          {sessions.map((s) => (
            <li key={s.name}>
              <button
                onClick={() => setSelected(s.name)}
                style={{
                  background: selected === s.name ? "#1f2833" : "transparent",
                  color: "#c5c6c7",
                  border: "1px solid #1f2833",
                  padding: "4px 8px",
                  cursor: "pointer",
                  width: "100%",
                  textAlign: "left",
                }}
              >
                {s.name}{" "}
                <span style={{ opacity: 0.6, fontSize: 12 }}>({s.kind})</span>
              </button>
            </li>
          ))}
        </ul>
        <pre
          style={{
            flex: 1,
            background: "#0a0a0a",
            color: "#c5c6c7",
            padding: 12,
            maxHeight: "70vh",
            overflowY: "auto",
            whiteSpace: "pre-wrap",
            wordBreak: "break-all",
          }}
        >
          {output || "(no output)"}
        </pre>
      </div>
      <p style={{ marginTop: 16, opacity: 0.6, fontSize: 12 }}>
        Read-only stream. Refreshes every ~1.5s.
      </p>
    </div>
  );
}
