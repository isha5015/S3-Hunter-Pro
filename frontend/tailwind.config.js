/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:      '#050505',
          panel:   '#0d0f12',
          card:    '#111418',
          border:  '#2a303c',
          accent:  '#00ff41',
          green:   '#00ff41',
          red:     '#ff003c',
          orange:  '#ff8c00',
          yellow:  '#ffd300',
          purple:  '#9d00ff',
          text:    '#e2e8f0',
          muted:   '#64748b',
        },
      },
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'], mono: ['JetBrains Mono', 'monospace'] },
      boxShadow: {
        glow:       '0 0 15px rgba(0,255,65,0.2)',
        'glow-red': '0 0 15px rgba(255,0,60,0.3)',
        'glow-grn': '0 0 20px rgba(0,255,136,0.25)',
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'scan-line':  'scanLine 2s linear infinite',
        'fade-in':    'fadeIn 0.4s ease-out',
        'slide-up':   'slideUp 0.3s ease-out',
      },
      keyframes: {
        scanLine: {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        fadeIn:  { from: { opacity: 0 }, to: { opacity: 1 } },
        slideUp: { from: { opacity: 0, transform: 'translateY(12px)' }, to: { opacity: 1, transform: 'translateY(0)' } },
      },
    },
  },
  plugins: [],
};
