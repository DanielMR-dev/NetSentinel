/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
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
          light: 'blue-500',
        },
        success: {
          DEFAULT: 'green-600',
          light: 'green-500',
        },
        warning: {
          DEFAULT: 'amber-500',
          light: 'amber-400',
        },
        danger: {
          DEFAULT: 'red-600',
          light: 'red-500',
        },
        surface: {
          DEFAULT: 'gray-800',
          light: 'gray-750',
        },
        background: 'gray-900',
      },
      boxShadow: {
        'card': '0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -2px rgba(0, 0, 0, 0.2)',
        'card-hover': '0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -4px rgba(0, 0, 0, 0.3)',
        'card-inner': 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.2)',
      },
      backgroundImage: {
        'gradient-primary': 'linear-gradient(to bottom, blue-600, blue-700)',
        'gradient-success': 'linear-gradient(to bottom, green-600, green-700)',
        'gradient-warning': 'linear-gradient(to bottom, amber-500, amber-600)',
        'gradient-danger': 'linear-gradient(to bottom, red-600, red-700)',
        'gradient-surface': 'linear-gradient(to bottom, gray-800, gray-750)',
        'shimmer': 'linear-gradient(to right, transparent, rgba(255,255,255,0.2), transparent)',
      },
      animation: {
        'shimmer': 'shimmer 2s infinite',
        'spin': 'spin 1s linear infinite',
        'pulse-slow': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        shimmer: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
      borderRadius: {
        'xl': '0.75rem',
        '2xl': '1rem',
      },
      spacing: {
        '18': '4.5rem',
        '22': '5.5rem',
      },
    },
  },
  plugins: [],
}