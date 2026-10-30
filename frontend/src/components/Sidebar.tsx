import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  FolderGit2,
  LogOut,
  Shield,
} from 'lucide-react';

interface SidebarProps {
  onLogout: () => void;
  currentUserEmail?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({ onLogout, currentUserEmail }) => {
  const links = [
    { to: '/', label: 'Overview', icon: LayoutDashboard },
    { to: '/projects', label: 'Projects & Scans', icon: FolderGit2 },
  ];

  return (
    <aside className="w-64 bg-gray-900/70 border-r border-gray-800 flex flex-col h-screen sticky top-0 backdrop-blur-md">
      {/* Brand */}
      <div className="h-16 flex items-center px-6 border-b border-gray-800 gap-3">
        <div className="p-2 bg-indigo-500/10 border border-indigo-500/20 rounded-lg text-indigo-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-sm font-semibold tracking-wide text-white">AI DevSecOps</h1>
          <p className="text-[10px] text-gray-400">Security & Gate Platform</p>
        </div>
      </div>

      {/* Nav Links */}
      <nav className="flex-1 px-4 py-6 space-y-1">
        {links.map((link) => {
          const Icon = link.icon;
          return (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-500/20'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              {link.label}
            </NavLink>
          );
        })}
      </nav>

      {/* User profile & Logout */}
      <div className="p-4 border-t border-gray-800 bg-gray-950/40">
        <div className="flex items-center justify-between">
          <div className="truncate pr-2">
            <p className="text-xs font-medium text-gray-200 truncate">
              {currentUserEmail || 'Security Engineer'}
            </p>
            <p className="text-[10px] text-emerald-400 font-mono">Authenticated</p>
          </div>
          <button
            onClick={onLogout}
            title="Sign out"
            className="p-1.5 text-gray-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-md transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
};
