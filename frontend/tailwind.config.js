/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Custom dark palette for the security platform
        gray: {
          950: '#0a0a0f',
        },
        // Severity colours (matches backend enum)
        severity: {
          critical: '#ef4444',  // red-500
          high:     '#f97316',  // orange-500
          medium:   '#eab308',  // yellow-500
          low:      '#3b82f6',  // blue-500
          info:     '#6b7280',  // gray-500
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
