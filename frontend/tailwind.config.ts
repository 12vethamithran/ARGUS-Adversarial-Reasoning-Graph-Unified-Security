import type { Config } from "tailwindcss";

/** Helper: a CSS var holding space-separated RGB channels, with Tailwind alpha support. */
const c = (v: string) => `rgb(var(${v}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // ── Theme-driven semantic tokens (resolve via [data-theme]) ──
        bg: {
          DEFAULT: c("--bg"),
          base:    c("--bg"),
          surface: c("--surface"),
          raised:  c("--raised"),
          overlay: c("--overlay"),
        },
        surface: c("--surface"),
        raised:  c("--raised"),
        overlay: c("--overlay"),
        line:    c("--border"),
        text: {
          primary:   c("--text"),
          secondary: c("--text-secondary"),
          muted:     c("--text-muted"),
        },
        // Primary accent flips per theme (sky-blue ↔ crimson).
        // Legacy names kept so existing classes auto-theme.
        accent: {
          DEFAULT: c("--accent"),
          strong:  c("--accent-strong"),
          cyan:    c("--accent"),
          amber:   c("--node-probing"),
          red:     c("--node-exploitable"),
          green:   "#22c55e",
        },
        node: {
          discovered:  c("--node-discovered"),
          probing:     c("--node-probing"),
          exploitable: c("--node-exploitable"),
          chained:     c("--node-chained"),
        },
        // Severity is fixed across themes (semantic meaning is constant).
        severity: {
          info: "#1e88e5",
          low: "#43a047",
          medium: "#d98a00",
          high: "#ff7043",
          critical: "#ff3d57",
        },
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "'Fira Code'", "monospace"],
        sans: ["'Inter'", "system-ui", "sans-serif"],
      },
      animation: {
        pulse_amber: "pulse_amber 1.2s ease-in-out infinite",
        "spin-slow": "spin 3s linear infinite",
        "fade-in": "fade-in 0.5s ease forwards",
        "fade-up": "fade-up 0.6s cubic-bezier(0.16,1,0.3,1) forwards",
      },
      keyframes: {
        pulse_amber: {
          "0%, 100%": { opacity: "1", boxShadow: "0 0 6px rgb(var(--accent))" },
          "50%": { opacity: "0.5", boxShadow: "0 0 18px rgb(var(--accent))" },
        },
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        "fade-up": { from: { opacity: "0", transform: "translateY(16px)" }, to: { opacity: "1", transform: "translateY(0)" } },
      },
    },
  },
  plugins: [],
} satisfies Config;
