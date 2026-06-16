import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Voidstrike",
  description: "Autonomous offensive security agent",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        suppressHydrationWarning
        style={{
          margin: 0,
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          background: "#0b0c10",
          color: "#c5c6c7",
        }}
      >
        <nav
          style={{
            borderBottom: "1px solid #1f2833",
            padding: "12px 24px",
            display: "flex",
            gap: 24,
          }}
        >
          <a href="/" style={{ color: "#66fcf1", textDecoration: "none" }}>
            voidstrike
          </a>
          <a href="/engagements" style={{ color: "#c5c6c7" }}>
            engagements
          </a>
          <a href="/hitl" style={{ color: "#c5c6c7" }}>
            hitl
          </a>
          <a href="/stuck" style={{ color: "#c5c6c7" }}>
            stuck
          </a>
          <a href="/skills" style={{ color: "#c5c6c7" }}>
            skills
          </a>
        </nav>
        <main style={{ padding: 24 }}>{children}</main>
      </body>
    </html>
  );
}
