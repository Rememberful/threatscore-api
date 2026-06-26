/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        navy:    "#0B132B",
        slate:   "#1C2541",
        offwhite:"#F4F5F7",
        steel:   "#5C6B73",
        blue:    "#3A86FF",
        crimson: "#D90429",
        amber:   "#F77F00",
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "monospace"],
        sans: ["'Inter'", "sans-serif"],
      },
    },
  },
  plugins: [],
}
