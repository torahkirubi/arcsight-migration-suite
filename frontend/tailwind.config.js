/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Text"', '"Segoe UI"', 'Roboto', 'Helvetica', 'Arial', 'sans-serif'],
        mono: ['"SFMono-Regular"', 'Consolas', '"Liberation Mono"', 'Menlo', 'Courier', 'monospace'],
      },
      colors: {
        obsidian: {
          950: '#06070a',
          900: '#0b0d13',
          850: '#10131c',
          800: '#161a26',
        },
      },
    },
  },
  plugins: [],
}
