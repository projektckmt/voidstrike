"use client";

import { useEffect, useState } from "react";
import { fetchHitlQueue, postStuckResponse } from "@/lib/gateway";

export default function StuckQueue() {
  // The HITL queue and stuck queue are the same channel; we filter on `kind`.
  const [reports, setReports] = useState<any[]>([]);
  const [draft, setDraft] = useState<Record<string, string>>({});

  useEffect(() => {
    const tick = async () => {
      try {
        const data = await fetchHitlQueue();
        setReports(
          (data.pending || []).filter((p: any) => p.kind === "stuck_report"),
        );
      } catch {
        /* */
      }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => clearInterval(id);
  }, []);

  async function respond(engagementId: string) {
    const guidance = draft[engagementId] || "";
    if (!guidance.trim()) return;
    await postStuckResponse(engagementId, guidance);
    setDraft({ ...draft, [engagementId]: "" });
  }

  return (
    <div>
      <h2>Stuck escalations</h2>
      {reports.length === 0 ? (
        <p style={{ opacity: 0.5 }}>Nothing stuck.</p>
      ) : (
        reports.map((r, i) => (
          <div
            key={i}
            style={{
              padding: 12,
              marginBottom: 12,
              border: "1px solid #1f2833",
              background: "#101418",
            }}
          >
            <h3 style={{ marginTop: 0 }}>
              {r.current_objective}{" "}
              <span style={{ opacity: 0.6, fontSize: 13 }}>
                eng={r.engagement_id?.slice(0, 8)}
              </span>
            </h3>

            <details>
              <summary>Tried ({r.attempts?.length})</summary>
              <ul>
                {(r.attempts || []).map((a: string, j: number) => (
                  <li key={j}>{a}</li>
                ))}
              </ul>
            </details>
            <details>
              <summary>Operator questions</summary>
              <ul>
                {(r.operator_questions || []).map((q: string, j: number) => (
                  <li key={j}>{q}</li>
                ))}
              </ul>
            </details>

            <textarea
              value={draft[r.engagement_id] || ""}
              onChange={(e) => setDraft({ ...draft, [r.engagement_id]: e.target.value })}
              placeholder="Your hint — what does the agent need to know?"
              style={{
                width: "100%",
                background: "#0a0a0a",
                color: "#c5c6c7",
                border: "1px solid #1f2833",
                padding: 6,
              }}
              rows={3}
            />
            <button
              onClick={() => respond(r.engagement_id)}
              style={{ marginTop: 8 }}
            >
              Resume with this guidance
            </button>
          </div>
        ))
      )}
    </div>
  );
}
