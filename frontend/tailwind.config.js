/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        navy: {
          50:  '#E8EEF6',
          100: '#C5D2E6',
          200: '#96AECE',
          300: '#6789B6',
          400: '#3F6AA0',
          500: '#2A508A',
          600: '#1E3D71',
          700: '#142D5A',
          800: '#0D2047',
          900: '#0B1F3A',
          950: '#071529',
        },
        teal: {
          400: '#2DD4BF',
          500: '#14B8A6',
          600: '#0D9488',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
};
