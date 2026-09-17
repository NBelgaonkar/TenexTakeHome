import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#07090c",
          900: "#0c1117",
          800: "#121821",
          700: "#1a2330",
          600: "#243044",
        },
        line: "#2a3644",
        mist: "#8b9bb0",
        foam: "#e8eef4",
        signal: {
          DEFAULT: "#3ee0c5",
          dim: "#1a6b5e",
        },
        alert: {
          high: "#ff5d6c",
          medium: "#f0b429",
          low: "#5b8def",
        },
      },
      fontFamily: {
        sans: ["var(--font-plex-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-plex-mono)", "ui-monospace", "monospace"],
      },
      boxShadow: {
        panel: "0 0 0 1px rgba(62, 224, 197, 0.08), 0 24px 80px rgba(0, 0, 0, 0.45)",
      },
    },
  },
  plugins: [],
};

export default config;
