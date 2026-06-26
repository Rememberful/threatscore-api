import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite" // Keep Tailwind v4 active!

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/auth":      "http://localhost:8000",
      "/api":       "http://localhost:8000",
      "/dashboard": "http://localhost:8000",
    }
  }
})