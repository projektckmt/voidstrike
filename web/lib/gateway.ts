/**
 * Gateway base URL — context-dependent.
 *
 * In Docker, the Next.js server (running inside the `web` container) and the
 * browser hitting localhost:3000 see different networks:
 *
 *   - **Server components / API routes** (typeof window === "undefined")
 *     run inside the container, so `localhost:8000` is the container itself
 *     (refused). They must hit `gateway:8000` via Docker's internal DNS.
 *
 *   - **Client components** (in the browser) reach the gateway through the
 *     host's port forward — `localhost:8000` works there.
 *
 * Inject `GATEWAY_INTERNAL_URL` for the server path; the existing
 * `NEXT_PUBLIC_GATEWAY_URL` stays the browser path.
 */
export const GATEWAY_URL: string =
  typeof window === "undefined"
    ? (process.env.GATEWAY_INTERNAL_URL ?? "http://gateway:8000")
    : (process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8000");

async function getJson<T = any>(path: string): Promise<T> {
  const r = await fetch(`${GATEWAY_URL}${path}`, { cache: "no-store" });
  if (!r.ok) throw new Error(`gateway ${r.status}: ${path}`);
  return r.json();
}

export async function listEngagements() {
  return getJson("/engagements");
}

export async function listProposedSkills() {
  return getJson("/skills/_proposed");
}

export async function fetchEpisodes(engagementId: string, n = 100) {
  return getJson(`/engagements/${engagementId}/episodes?n=${n}`);
}

export async function fetchFindings(engagementId: string) {
  return getJson(`/engagements/${engagementId}/findings`);
}

export async function fetchLabProgress(engagementId: string) {
  return getJson(`/engagements/${engagementId}/lab_progress`);
}

export async function fetchGraph(engagementId: string) {
  return getJson(`/engagements/${engagementId}/graph`);
}

export async function fetchShells(engagementId: string) {
  return getJson(`/engagements/${engagementId}/shells`);
}

export async function readShell(engagementId: string, sessionName: string) {
  return getJson(`/engagements/${engagementId}/shell/${sessionName}/read`);
}

export async function fetchReport(engagementId: string) {
  return getJson<{ exists: boolean; markdown: string }>(
    `/engagements/${engagementId}/report`,
  );
}

export async function fetchStuck(engagementId: string) {
  return getJson(`/engagements/${engagementId}/stuck`);
}

export async function fetchHitlQueue() {
  return getJson("/hitl/queue");
}

export async function postApproval(
  engagementId: string,
  body: { decision: string; guidance?: string; edited_args?: any },
) {
  const r = await fetch(`${GATEWAY_URL}/engagements/${engagementId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`gateway ${r.status}`);
  return r.json();
}

export async function postStuckResponse(engagementId: string, guidance: string) {
  const r = await fetch(
    `${GATEWAY_URL}/engagements/${engagementId}/stuck_response`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ engagement_id: engagementId, guidance }),
    },
  );
  if (!r.ok) throw new Error(`gateway ${r.status}`);
  return r.json();
}
