"use client";

import { type CSSProperties, useMemo, useState } from "react";

const OUTCOME_COLOR: Record<string, string> = {
  new_finding: "#7fd178",
  flag: "#66fcf1",
  shell: "#7fd178",
  error: "#ff5b5b",
  failed: "#ff5b5b",
  no_result: "#6b7785",
};

const PRE_STYLE: CSSProperties = {
  background: "#0d1117",
  padding: 8,
  margin: "2px 0 0",
  borderRadius: 4,
  maxHeight: 320,
  overflow: "auto",
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
  fontSize: 12,
};

const LABEL_STYLE: CSSProperties = {
  fontSize: 10,
  letterSpacing: 1,
  textTransform: "uppercase",
  opacity: 0.45,
};

// Low-signal actions: reads/plumbing that the agent does to orient itself but
// that don't represent an attack step. The hide-meta toggle drops these.
const META_ACTIONS = [
  "read_episode_tail", "read_engagement", "summarize_engagement",
  "list_findings", "tmux_read", "tmux_list_sessions", "write_objective",
];

function isMeta(action: string): boolean {
  const a = (action || "").toLowerCase();
  return META_ACTIONS.some((m) => a.includes(m));
}

// Pull a one-line, human-meaningful preview out of tool_input so a row like
// `shell__tmux_exec` shows the actual command instead of nothing.
function inputPreview(input: any): string {
  if (!input || typeof input !== "object") {
    return typeof input === "string" ? input : "";
  }
  const keys = [
    "cmd", "command", "keys", "query", "filter", "url",
    "host", "target", "path", "args", "share", "user",
  ];
  for (const k of keys) {
    const v = input[k];
    if (typeof v === "string" && v.trim()) return v.trim();
    if (Array.isArray(v) && v.length) return v.join(" ");
  }
  try {
    const s = JSON.stringify(input);
    return s === "{}" ? "" : s;
  } catch {
    return "";
  }
}

function fmtDuration(ms: number): string {
  if (!ms) return "";
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

const ctrl: CSSProperties = {
  background: "#0d1117",
  border: "1px solid #1f2833",
  color: "#c9d6e3",
  borderRadius: 4,
  padding: "3px 6px",
  fontSize: 13,
};

export default function EpisodeTimeline({ episodes }: { episodes: any[] }) {
  const [query, setQuery] = useState("");
  const [agent, setAgent] = useState("");
  const [hideNoResult, setHideNoResult] = useState(false);
  const [hideMeta, setHideMeta] = useState(false);

  const agents = useMemo(
    () => Array.from(new Set(episodes.map((e) => e.agent_name).filter(Boolean))).sort(),
    [episodes],
  );

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return episodes.filter((e) => {
      if (agent && e.agent_name !== agent) return false;
      if (hideNoResult && e.outcome_tag === "no_result") return false;
      if (hideMeta && isMeta(e.action)) return false;
      if (q) {
        const hay = [
          e.action, e.agent_name, e.outcome_tag,
          inputPreview(e.tool_input), e.tool_output, e.error,
        ].join(" ").toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [episodes, query, agent, hideNoResult, hideMeta]);

  return (
    <section>
      <h3>
        Episode timeline{" "}
        <span style={{ opacity: 0.5, fontSize: 14, fontWeight: "normal" }}>
          (showing {visible.length} of {episodes.length})
        </span>
      </h3>

      <div
        style={{
          display: "flex",
          gap: 14,
          alignItems: "center",
          flexWrap: "wrap",
          margin: "4px 0 12px",
        }}
      >
        <input
          type="text"
          placeholder="search action / command / output…"
          value={query}
          onChange={(ev) => setQuery(ev.target.value)}
          style={{ ...ctrl, minWidth: 260, flex: "1 1 260px" }}
        />
        <select value={agent} onChange={(ev) => setAgent(ev.target.value)} style={ctrl}>
          <option value="">all agents</option>
          {agents.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <label style={{ display: "flex", gap: 5, alignItems: "center", fontSize: 13 }}>
          <input
            type="checkbox"
            checked={hideNoResult}
            onChange={(ev) => setHideNoResult(ev.target.checked)}
          />
          hide no-result
        </label>
        <label style={{ display: "flex", gap: 5, alignItems: "center", fontSize: 13 }}>
          <input
            type="checkbox"
            checked={hideMeta}
            onChange={(ev) => setHideMeta(ev.target.checked)}
          />
          hide reads/plumbing
        </label>
        {(query || agent || hideNoResult || hideMeta) && (
          <button
            type="button"
            onClick={() => {
              setQuery("");
              setAgent("");
              setHideNoResult(false);
              setHideMeta(false);
            }}
            style={{ ...ctrl, cursor: "pointer" }}
          >
            clear
          </button>
        )}
      </div>

      {visible.length === 0 ? (
        <p style={{ opacity: 0.5 }}>No episodes match the current filters.</p>
      ) : (
        visible.map((e) => {
          const preview = inputPreview(e.tool_input);
          const dur = fmtDuration(e.duration_ms);
          const outcomeColor = OUTCOME_COLOR[e.outcome_tag] || "#9fb0c0";
          const hasInput =
            e.tool_input &&
            typeof e.tool_input === "object" &&
            Object.keys(e.tool_input).length > 0;
          const output = (e.tool_output || "").slice(0, 4000);
          const truncated = (e.tool_output || "").length > 4000;
          const expandable = hasInput || !!e.tool_output || !!e.error;
          return (
            <details
              key={e.id}
              style={{ borderBottom: "1px solid #1f2833", padding: "5px 0" }}
            >
              <summary
                style={{
                  cursor: expandable ? "pointer" : "default",
                  display: "grid",
                  gridTemplateColumns: "150px 70px 1fr auto",
                  gap: 10,
                  alignItems: "baseline",
                  listStyle: expandable ? undefined : "none",
                }}
              >
                <span style={{ opacity: 0.55, fontVariantNumeric: "tabular-nums" }}>
                  {e.timestamp?.slice(0, 19).replace("T", " ")}
                </span>
                <span style={{ color: "#9fb0c0" }}>{e.agent_name}</span>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  <code style={{ color: "#c9d6e3" }}>{e.action}</code>
                  {preview && <span style={{ opacity: 0.6 }}> — {preview.slice(0, 140)}</span>}
                </span>
                <span style={{ display: "flex", gap: 12, alignItems: "baseline" }}>
                  {dur && <span style={{ opacity: 0.45 }}>{dur}</span>}
                  <span style={{ color: outcomeColor }}>{e.outcome_tag}</span>
                  <span style={{ opacity: 0.45, fontVariantNumeric: "tabular-nums" }}>
                    ${Number(e.cost_usd || 0).toFixed(4)}
                  </span>
                </span>
              </summary>
              {expandable && (
                <div style={{ padding: "8px 12px", display: "flex", flexDirection: "column", gap: 10 }}>
                  {hasInput && (
                    <div>
                      <div style={LABEL_STYLE}>input</div>
                      <pre style={PRE_STYLE}>{JSON.stringify(e.tool_input, null, 2)}</pre>
                    </div>
                  )}
                  {e.error && (
                    <div>
                      <div style={{ ...LABEL_STYLE, color: "#ff5b5b", opacity: 0.8 }}>error</div>
                      <pre style={{ ...PRE_STYLE, color: "#ff9a9a" }}>{e.error}</pre>
                    </div>
                  )}
                  {e.tool_output && (
                    <div>
                      <div style={LABEL_STYLE}>output{truncated ? " (truncated)" : ""}</div>
                      <pre style={PRE_STYLE}>
                        {output}
                        {truncated ? "\n… (truncated)" : ""}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </details>
          );
        })
      )}
    </section>
  );
}
