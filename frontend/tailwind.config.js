/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // Bank of India brand palette
        boi: {
          navy: "#1a2b5c",     // sidebar / deep headers
          blue: "#1e5eb8",     // primary action / links
          sky: "#eaf1fb",      // tinted surfaces / hovers
          saffron: "#f57c00",  // logo star / accents
          red: "#c8102e",      // brand red / critical
        },
        // Severity scale (single source of truth, mirrored in src/lib/theme.js)
        sev: {
          low: "#2e7d32",
          medium: "#f9a825",
          high: "#ef6c00",
          critical: "#c8102e",
        },
        surface: {
          app: "#e9edf5",      // app background (grayer so white cards pop)
          card: "#ffffff",     // card background
        },
      },
      // Enlarged type scale — bumps every named text utility ~+12% for a more
      // readable, higher-impact UI (paired with the arbitrary-px sizes in JSX).
      fontSize: {
        xs: ["0.8125rem", "1.15rem"],   // 13px
        sm: ["0.9375rem", "1.4rem"],    // 15px
        base: ["1.0625rem", "1.65rem"], // 17px
        lg: ["1.1875rem", "1.75rem"],   // 19px
        xl: ["1.375rem", "1.9rem"],     // 22px
        "2xl": ["1.625rem", "2.05rem"], // 26px
        "3xl": ["1.875rem", "2.3rem"],  // 30px
        "4xl": ["2.5rem", "2.7rem"],    // 40px
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "SF Mono", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        card: "0 2px 4px rgba(16, 24, 40, 0.10), 0 10px 24px -4px rgba(16, 24, 40, 0.20)",
        cardhover: "0 6px 12px rgba(16, 24, 40, 0.12), 0 22px 44px -8px rgba(16, 24, 40, 0.28)",
        sidebar: "2px 0 18px rgba(16, 24, 40, 0.16)",
      },
      borderRadius: {
        xl2: "1rem",
      },
      keyframes: {
        findingFlash: {
          "0%": { boxShadow: "0 0 0 0 rgba(30,94,184,0.5)", borderColor: "#1e5eb8" },
          "100%": { boxShadow: "0 0 0 8px rgba(30,94,184,0)" },
        },
        impPulse: {
          "0%": { boxShadow: "0 0 0 0 rgba(200,16,46,0.45)" },
          "100%": { boxShadow: "0 0 0 14px rgba(200,16,46,0)" },
        },
      },
      animation: {
        findingFlash: "findingFlash 1.1s ease-out",
        impPulse: "impPulse 1.4s ease-out",
      },
    },
  },
  plugins: [],
};
