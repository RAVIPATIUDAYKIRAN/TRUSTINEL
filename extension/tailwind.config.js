/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./popup/index.html",
    "./popup/src/**/*.{js,ts,jsx,tsx}",
    "./background/**/*.ts",
    "./content/**/*.ts"
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          dark: '#0B0F19',
          card: '#151D30',
          accent: '#3B82F6',
          success: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
        }
      }
    },
  },
  plugins: [],
}
