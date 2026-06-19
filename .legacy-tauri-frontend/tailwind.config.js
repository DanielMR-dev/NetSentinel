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
          DEFAULT: '#2563eb',
          hover: '#1d4ed8',
          light: '#3b82f6',
        },
        success: {
          DEFAULT: '#16a34a',
          light: '#22c55e',
        },
        warning: {
          DEFAULT: '#f59e0b',
          light: '#fbbf24',
        },
        danger: {
          DEFAULT: '#dc2626',
          light: '#ef4444',
        },
        gray: {
          750: '#27303f',
        },
        surface: {
          DEFAULT: '#1f2937',
          light: '#27303f',
        },
        background: '#111827',
      },
      boxShadow: {
        'card': '0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -2px rgba(0, 0, 0, 0.2)',
        'card-hover': '0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -4px rgba(0, 0, 0, 0.3)',
        'card-inner': 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.2)',
      },
      backgroundImage: {
        'gradient-primary': 'linear-gradient(to bottom, #2563eb, #1d4ed8)',
        'gradient-success': 'linear-gradient(to bottom, #16a34a, #15803d)',
        'gradient-warning': 'linear-gradient(to bottom, #f59e0b, #d97706)',
        'gradient-danger': 'linear-gradient(to bottom, #dc2626, #b91c1c)',
        'gradient-surface': 'linear-gradient(to bottom, #1f2937, #27303f)',
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