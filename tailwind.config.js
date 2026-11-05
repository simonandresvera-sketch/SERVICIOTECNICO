/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './*.html',
    './src/**/*.{html,js}'
  ],
  theme: {
    extend: {
      colors: {
        'bg-base': '#050814',
        ink: '#e6f1ff',
        primary: '#00f0ff',
        secondary: '#1a1f3a',
        muted: '#93a4c9'
      },
      fontFamily: {
        sans: ['Space Grotesk', 'system-ui', 'sans-serif']
      }
    }
  },
  plugins: []
};
