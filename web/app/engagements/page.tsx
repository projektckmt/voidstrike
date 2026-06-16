"use client";

import { useEffect, useState } from "react";
import { listEngagements } from "@/lib/gateway";

type Engagement = {
  engagement_id: string;
  name?: string;
  mode?: string;
  targets?: string[];
};

export default function Engagements() {
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const data = await listEngagements();
        if (!cancelled) {
          setEngagements(data.engagements || []);
          setError(null);
        }
      } catch (e: any) {
        if (!cancelled) setError(String(e));
      }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return (
    <div>
      <h2>Engagements</h2>
      {error && (
        <p style={{ color: "#ff8a3b" }}>
          Gateway error: {error} (retrying every 3s)
        </p>
      )}
      {engagements.length === 0 ? (
        <p style={{ opacity: 0.5 }}>None yet. Start one with the CLI.</p>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #1f2833" }}>
              <th style={{ textAlign: "left", padding: 6 }}>id</th>
              <th style={{ textAlign: "left", padding: 6 }}>name</th>
              <th style={{ textAlign: "left", padding: 6 }}>mode</th>
              <th style={{ textAlign: "left", padding: 6 }}>targets</th>
            </tr>
          </thead>
          <tbody>
            {engagements.map((e) => (
              <tr key={e.engagement_id}>
                <td style={{ padding: 6 }}>
                  <a
                    href={`/engagements/${e.engagement_id}`}
                    style={{ color: "#66fcf1" }}
                  >
                    {e.engagement_id.slice(0, 8)}
                  </a>
                </td>
                <td style={{ padding: 6 }}>{e.name || "—"}</td>
                <td style={{ padding: 6 }}>{e.mode || "—"}</td>
                <td style={{ padding: 6 }}>
                  {(e.targets || []).join(", ") || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p style={{ marginTop: 16, opacity: 0.4, fontSize: 12 }}>
        Refreshes every 3s.
      </p>
    </div>
  );
}
