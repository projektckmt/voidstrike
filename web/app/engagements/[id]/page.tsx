import {
  fetchEpisodes,
  fetchFindings,
  fetchLabProgress,
  fetchReport,
  fetchShells,
} from "@/lib/gateway";
import EpisodeTimeline from "./EpisodeTimeline";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ff3b3b",
  high: "#ff8a3b",
  medium: "#ffd13b",
  low: "#7fd178",
  info: "#7fbfd1",
};

export default async function Engagement({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const [episodesData, findingsData, labData, shellsData, reportData] =
    await Promise.all([
      fetchEpisodes(id, 200).catch(() => ({ episodes: [] })),
      fetchFindings(id).catch(() => ({ findings: [] })),
      fetchLabProgress(id).catch(() => ({ progress: {}, hosts: [] })),
      fetchShells(id).catch(() => ({ sessions: [] })),
      fetchReport(id).catch(() => ({ exists: false, markdown: "" })),
    ]);

  return (
    <div>
      <h2>
        Engagement <code style={{ color: "#66fcf1" }}>{id.slice(0, 8)}</code>
      </h2>
      <nav style={{ marginBottom: 16, display: "flex", gap: 16 }}>
        <a href={`/engagements/${id}/shell`} style={{ color: "#66fcf1" }}>shell view</a>
        <a href={`/engagements/${id}/graph`} style={{ color: "#66fcf1" }}>graph view</a>
        {reportData.exists && (
          <a href={`/engagements/${id}/report`} style={{ color: "#66fcf1" }}>report view</a>
        )}
      </nav>

      {Object.keys(labData.progress).length > 0 && (
        <section style={{ marginBottom: 24 }}>
          <h3>Lab progress</h3>
          <pre style={{ background: "#1f2833", padding: 8 }}>
            {JSON.stringify(labData.progress, null, 2)}
          </pre>
        </section>
      )}

      <section style={{ marginBottom: 24 }}>
        <h3>Active shells</h3>
        {shellsData.sessions.length === 0 ? (
          <p style={{ opacity: 0.5 }}>None.</p>
        ) : (
          <ul>
            {shellsData.sessions.map((s: any) => (
              <li key={s.name}>
                <a href={`/engagements/${id}/shell?session=${s.name}`}>{s.name}</a> ({s.kind})
              </li>
            ))}
          </ul>
        )}
      </section>

      <section style={{ marginBottom: 24 }}>
        <h3>Findings ({findingsData.findings.length})</h3>
        {findingsData.findings.map((f: any) => (
          <div
            key={f.id}
            style={{
              borderLeft: `4px solid ${SEVERITY_COLOR[f.severity] || "#666"}`,
              padding: "4px 12px",
              marginBottom: 8,
              background: "#101418",
            }}
          >
            <strong>{f.title}</strong>{" "}
            <span style={{ opacity: 0.6 }}>
              [{f.severity}] {f.host}
            </span>
            <div style={{ opacity: 0.8 }}>{f.description}</div>
            {f.cve?.length > 0 && (
              <div style={{ opacity: 0.6 }}>CVE: {f.cve.join(", ")}</div>
            )}
          </div>
        ))}
      </section>

      <EpisodeTimeline episodes={episodesData.episodes} />
    </div>
  );
}
