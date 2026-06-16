"use client";

import { useEffect, useState } from "react";
import { fetchHitlQueue, postApproval } from "@/lib/gateway";

export default function HitlQueue() {
  const [pending, setPending] = useState<any[]>([]);
  const [guidance, setGuidance] = useState<string>("");

  useEffect(() => {
    const tick = async () => {
      try {
        const data = await fetchHitlQueue();
        setPending(data.pending || []);
      } catch {
        /* */
      }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => clearInterval(id);
  }, []);

  async function decide(engagementId: string, decision: string) {
    await postApproval(engagementId, { decision, guidance });
    setGuidance("");
  }

  return (
    <div>
      <h2>HITL approval queue</h2>
      {pending.length === 0 ? (
        <p style={{ opacity: 0.5 }}>Nothing waiting.</p>
      ) : (
        pending.map((item, i) => (
          <div
            key={i}
            style={{
              padding: 12,
              marginBottom: 12,
              border: "1px solid #1f2833",
              background: "#101418",
            }}
          >
            <div>
              <strong>{item.tool}</strong>{" "}
              <span style={{ opacity: 0.6 }}>
                [{item.action_class}] eng={item.engagement_id?.slice(0, 8)}
              </span>
            </div>
            <pre style={{ background: "#0a0a0a", padding: 8, fontSize: 12 }}>
              {JSON.stringify(item.args, null, 2)}
            </pre>
            <textarea
              value={guidance}
              onChange={(e) => setGuidance(e.target.value)}
              placeholder="Optional guidance / reason"
              style={{
                width: "100%",
                background: "#0a0a0a",
                color: "#c5c6c7",
                border: "1px solid #1f2833",
                padding: 6,
              }}
              rows={2}
            />
            <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
              <button onClick={() => decide(item.engagement_id, "accept")}>
                Accept
              </button>
              <button onClick={() => decide(item.engagement_id, "reject")}>
                Reject
              </button>
            </div>
          </div>
        ))
      )}
    </div>
  );
}
