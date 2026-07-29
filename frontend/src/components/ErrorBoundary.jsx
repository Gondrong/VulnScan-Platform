import React from "react";

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error("[ErrorBoundary]", error, info.componentStack);
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "center",
        minHeight: "100vh", padding: "2rem",
        background: "var(--bg-0, #111)", color: "var(--fg-1, #ccc)",
        fontFamily: "Inter, system-ui, sans-serif",
      }}>
        <div style={{
          maxWidth: 480, textAlign: "center",
          background: "var(--bg-1, #1a1a1a)", borderRadius: 12,
          padding: "2.5rem 2rem", border: "1px solid var(--border, #333)",
        }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>!</div>
          <h2 style={{ margin: "0 0 0.5rem", fontSize: 20, color: "var(--fg-0, #fff)" }}>
            Something went wrong
          </h2>
          <p style={{ margin: "0 0 1.5rem", fontSize: 14, lineHeight: 1.5, opacity: 0.7 }}>
            An unexpected error occurred. Try reloading the page.
          </p>
          <details style={{ textAlign: "left", marginBottom: "1.5rem", fontSize: 12, opacity: 0.5 }}>
            <summary style={{ cursor: "pointer", marginBottom: 8 }}>Error details</summary>
            <pre style={{
              whiteSpace: "pre-wrap", wordBreak: "break-word",
              background: "var(--bg-0, #111)", padding: 12, borderRadius: 6,
              maxHeight: 200, overflow: "auto",
            }}>
              {this.state.error?.toString()}
            </pre>
          </details>
          <button
            onClick={() => window.location.reload()}
            style={{
              padding: "0.6rem 1.5rem", borderRadius: 6,
              background: "var(--accent, #5b8def)", color: "#fff",
              border: "none", cursor: "pointer", fontSize: 14, fontWeight: 500,
            }}
          >
            Reload page
          </button>
        </div>
      </div>
    );
  }
}
