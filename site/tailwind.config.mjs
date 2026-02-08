/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './src/pages/index.astro',
    './src/components/landing/**/*.astro',
    './src/layouts/LandingLayout.astro',
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: '#FF9900',
          hover: '#FFCC66',
          active: '#E68A00',
          light: '#FFF8E8',
          dark: '#1A1A2E',
        },
      },
      fontFamily: {
        sans: [
          '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto',
          '"Helvetica Neue"', 'Arial', 'sans-serif',
        ],
        mono: [
          '"SF Mono"', '"Fira Code"', '"Fira Mono"', 'Menlo', 'Consolas',
          'monospace',
        ],
      },
    },
  },
  plugins: [],
};
