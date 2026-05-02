/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: 'blue-600',
          hover: 'blue-700',
        },
        success: 'green-600',
        warning: 'amber-500',
        danger: 'red-600',
        surface: 'gray-800',
        background: 'gray-900',
      },
    },
  },
  plugins: [],
}