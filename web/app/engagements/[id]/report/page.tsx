import type { CSSProperties } from "react";
import ReactMarkdown from "react-markdown";
import { fetchReport } from "@/lib/gateway";

// Wrap long lines. The verbatim-command appendix has unbroken tokens (base64,
// hashes, long URLs) and a default <pre> (white-space: pre) overflows the page
// horizontally. pre-wrap keeps the formatting but wraps; overflow-wrap/word-break
// force the unbreakable tokens to wrap too.
const WRAP: CSSProperties = {
  whiteSpace: "pre-wrap",
  overflowWrap: "anywhere",
  wordBreak: "break-word",
};

const mdComponents = {
  pre: (props: any) => (
    <pre style={{ ...WRAP, background: "#0b0c10", padding: 12, borderRadius: 4 }} {...props} />
  ),
  code: (props: any) => (
    <code style={{ overflowWrap: "anywhere", wordBreak: "break-word" }} {...props} />
  ),
};

export default async function Report({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const report = await fetchReport(id).catch(() => ({
    exists: false,
    markdown: "",
  }));

  return (
    <div>
      <h2>
        Report <code style={{ color: "#66fcf1" }}>{id.slice(0, 8)}</code>
      </h2>
      <nav style={{ marginBottom: 16 }}>
        <a href={`/engagements/${id}`} style={{ color: "#66fcf1" }}>
          ← back to engagement
        </a>
      </nav>

      {report.exists ? (
        // react-markdown escapes raw HTML by default — report content includes
        // output from compromised targets, so we don't render embedded HTML.
        <article
          style={{
            background: "#101418",
            padding: "16px 24px",
            lineHeight: 1.5,
            maxWidth: 900,
            overflowWrap: "anywhere",
          }}
        >
          <ReactMarkdown components={mdComponents}>{report.markdown}</ReactMarkdown>
        </article>
      ) : (
        <p style={{ opacity: 0.5 }}>No report yet.</p>
      )}
    </div>
  );
}
