import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, ListChecks, FolderSearch,
  History, FileBarChart2, Bot, Shield, Zap
} from 'lucide-react';

const links = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/payloads',  icon: ListChecks,      label: 'Payloads' },
  { to: '/explorer',  icon: FolderSearch,    label: 'Bucket Explorer' },
  { to: '/history',   icon: History,         label: 'Session History' },
  { to: '/reports',   icon: FileBarChart2,   label: 'Reports' },
  { to: '/ai',        icon: Bot,             label: 'AI Assistant' },
];

export default function Navbar() {
  return (
    <aside className="fixed top-0 left-0 h-screen w-64 bg-cyber-panel border-r border-cyber-border flex flex-col z-50">
      {/* Logo */}
      <div className="px-5 py-6 border-b border-cyber-border">
        <div className="flex items-center gap-3">
          <div className="relative w-9 h-9 flex items-center justify-center">
            <div className="absolute inset-0 rounded-lg bg-cyber-accent/20 animate-pulse-slow" />
            <Shield className="w-5 h-5 text-cyber-accent relative z-10" />
          </div>
          <div>
            <h1 className="font-bold text-white text-sm leading-none">S3-Hunter Pro</h1>
            <p className="text-cyber-muted text-xs mt-0.5 mono">v1.0.0 · AI Enhanced</p>
          </div>
        </div>
      </div>

      {/* Status pill */}
      <div className="px-5 py-3 border-b border-cyber-border">
        <div className="flex items-center gap-2 text-xs">
          <Zap className="w-3 h-3 text-cyber-green" />
          <span className="text-cyber-green font-medium">System Online</span>
        </div>
      </div>

      {/* Nav links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {links.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group
               ${isActive
                 ? 'bg-cyber-accent/15 text-cyber-accent border border-cyber-accent/30 shadow-glow'
                 : 'text-cyber-muted hover:text-cyber-text hover:bg-cyber-card'
               }`
            }
          >
            {({ isActive }) => (
              <>
                <Icon className={`w-4 h-4 flex-shrink-0 ${isActive ? 'text-cyber-accent' : 'text-cyber-muted group-hover:text-cyber-text'}`} />
                {label}
                {isActive && <div className="ml-auto w-1.5 h-1.5 rounded-full bg-cyber-accent animate-pulse" />}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-cyber-border">
        <p className="text-cyber-muted text-xs">For authorized testing only</p>
        <p className="text-cyber-muted/50 text-xs mt-0.5">© 2025 S3-Hunter Pro</p>
      </div>
    </aside>
  );
}
