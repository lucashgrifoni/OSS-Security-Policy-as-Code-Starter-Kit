module.exports = {
  content: ["./index.html", "./app.jsx", "./parts/**/*.jsx"],
  theme: {
    extend: {
      colors: {
        ink: "#0c124c",
        mist: "#d5d8dd",
        signal: "#08b98b",
        steel: "#9aa6b2",
        slate: "#7c8394",
        "ink-deep": "#070a30",
        "ink-soft": "#0f1660",
      },
      fontFamily: {
        sans: ['"Outfit"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      boxShadow: {
        glow: "0 0 60px -12px rgba(8,185,139,0.45)",
        "glow-sm": "0 0 32px -8px rgba(8,185,139,0.35)",
        "glow-lg": "0 0 90px -10px rgba(8,185,139,0.55)",
        panel: "0 25px 80px -20px rgba(0,0,0,0.55)",
        floor: "0 40px 100px -40px rgba(8,185,139,0.45), 0 25px 60px -20px rgba(0,0,0,0.6)",
      },
    },
  },
};
