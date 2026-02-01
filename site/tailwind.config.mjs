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
          DEFAULT: '#3EB065',
          hover: '#7CCF83',
          active: '#2D9050',
          light: '#F0FFF4',
          dark: '#152033',
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
