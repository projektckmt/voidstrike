import { fetchGraph } from "@/lib/gateway";

export default async function GraphView({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const data = await fetchGraph(id).catch(() => ({
    hosts: [],
    services: [],
    credentials: [],
    cves: [],
  }));

  return (
    <div>
      <h2>Graph projection ({id.slice(0, 8)})</h2>

      <section style={{ marginBottom: 16 }}>
        <h3>Hosts ({data.hosts.length})</h3>
        <ul>
          {data.hosts.map((h: any) => (
            <li key={h.address}>{h.address}</li>
          ))}
        </ul>
      </section>

      <section style={{ marginBottom: 16 }}>
        <h3>Services ({data.services.length})</h3>
        <table>
          <thead>
            <tr>
              <th style={{ textAlign: "left", padding: 4 }}>host</th>
              <th style={{ textAlign: "left", padding: 4 }}>port</th>
              <th style={{ textAlign: "left", padding: 4 }}>service</th>
              <th style={{ textAlign: "left", padding: 4 }}>version</th>
            </tr>
          </thead>
          <tbody>
            {data.services.map((s: any, i: number) => (
              <tr key={i}>
                <td style={{ padding: 4 }}>{s.host}</td>
                <td style={{ padding: 4 }}>{s.port}</td>
                <td style={{ padding: 4 }}>{s.service || "—"}</td>
                <td style={{ padding: 4 }}>{s.version || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section style={{ marginBottom: 16 }}>
        <h3>Credentials ({data.credentials.length})</h3>
        <ul>
          {data.credentials.map((c: any, i: number) => (
            <li key={i}>
              {c.type} on {c.host} — {c.source}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h3>Vulns ({data.cves.length})</h3>
        <ul>
          {data.cves.map((c: any) => (
            <li key={c.cve}>{c.cve}</li>
          ))}
        </ul>
      </section>

      <p style={{ marginTop: 24, opacity: 0.5, fontSize: 12 }}>
        Derived from the episode log via the ETL worker. If something looks
        wrong, the log is authoritative — graph can be rebuilt.
      </p>
    </div>
  );
}
