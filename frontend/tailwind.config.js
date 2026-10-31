/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#0B1120",
        surface: "#131B2E",
        "surface-raised": "#1A2438",
        border: "#253248",
        "border-bright": "#334259",
        "text-primary": "#E7ECF5",
        "text-secondary": "#8B97AC",
        "text-muted": "#5B6B85",
        accent: {
          DEFAULT: "#FFB454",
          dim: "#B8853D",
          bright: "#FFD08A",
        },
        severity: {
          low: "#5B9BD5",
          medium: "#E8B94A",
          high: "#E8734A",
          critical: "#E24B4B",
        },
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};

