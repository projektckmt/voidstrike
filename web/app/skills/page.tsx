import { listProposedSkills } from "@/lib/gateway";

export default async function SkillProposals() {
  const data = await listProposedSkills().catch(() => ({ proposals: [] }));
  return (
    <div>
      <h2>Proposed skills</h2>
      {data.proposals.length === 0 ? (
        <p style={{ opacity: 0.6 }}>No pending proposals.</p>
      ) : (
        data.proposals.map((p: any) => (
          <details key={p.name} style={{ marginBottom: 16 }}>
            <summary style={{ color: "#66fcf1" }}>{p.name}</summary>
            <pre
              style={{
                background: "#1f2833",
                padding: 12,
                overflowX: "auto",
                whiteSpace: "pre-wrap",
              }}
            >
              {p.preview}
            </pre>
          </details>
        ))
      )}
    </div>
  );
}
