import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      colors: {
        matrix: {
          DEFAULT: "#00ff9c",
          dim: "#0a8f5b",
          dark: "#031a12",
        },
        sev: {
          critical: "#ff2d55",
          high: "#ff6b35",
          medium: "#ffd23f",
          low: "#3fa7ff",
          info: "#9aa0a6",
        },
      },
      boxShadow: {
        glow: "0 0 24px rgba(0,255,156,0.25)",
        "glow-strong": "0 0 40px rgba(0,255,156,0.45)",
      },
      keyframes: {
        flicker: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.82" },
        },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        "fade-in": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        flicker: "flicker 3s ease-in-out infinite",
        scan: "scan 4s linear infinite",
        "fade-in": "fade-in 0.25s ease-out",
      },
    },
  },
  plugins: [],
};

export default config;
