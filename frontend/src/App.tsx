import { useState, useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { Dashboard } from './pages/Dashboard';
import { Projects } from './pages/Projects';
import { ProjectDetail } from './pages/ProjectDetail';
import { Login } from './pages/Login';
import { authApi } from './api/client';
import { Shield, ExternalLink } from 'lucide-react';

export function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('token'));
  const [user, setUser] = useState<any>(null);
  const [checkingAuth, setCheckingAuth] = useState(true);

  useEffect(() => {
    const verifyAuth = async () => {
      const storedToken = localStorage.getItem('token');
      if (storedToken) {
        try {
          const userData = await authApi.getMe();
          setUser(userData);
          setToken(storedToken);
        } catch (err) {
          localStorage.removeItem('token');
          localStorage.removeItem('refresh_token');
          setToken(null);
          setUser(null);
        }
      }
      setCheckingAuth(false);
    };
    verifyAuth();
  }, []);

  const handleLoginSuccess = (newToken: string, userData: any) => {
    localStorage.setItem('token', newToken);
    setToken(newToken);
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('refresh_token');
    setToken(null);
    setUser(null);
  };

  if (checkingAuth) {
    return (
      <div className="min-h-screen bg-gray-950 text-gray-400 flex items-center justify-center">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Shield className="w-5 h-5 text-indigo-500 animate-pulse" />
          Loading AI DevSecOps Platform...
        </div>
      </div>
    );
  }

  if (!token) {
    return (
      <div className="min-h-screen flex flex-col justify-between bg-gray-950">
        <Login onLoginSuccess={handleLoginSuccess} />
        {/* Footer links for convenience & test compatibility */}
        <div className="pb-4 text-center text-xs text-gray-500 flex items-center justify-center gap-4">
          <span>Phase 1 — Complete ✓</span>
          <a href="/api/health" target="_blank" rel="noreferrer" className="hover:text-indigo-400">
            API Health
          </a>
          <a href="/api/docs" target="_blank" rel="noreferrer" className="hover:text-indigo-400">
            API Docs
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-gray-950 text-gray-100 font-sans">
      <Sidebar onLogout={handleLogout} currentUserEmail={user?.email} />
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Top Navbar */}
        <header className="h-16 border-b border-gray-800 bg-gray-900/40 backdrop-blur-md px-8 flex items-center justify-between sticky top-0 z-30">
          <div className="flex items-center gap-3">
            <span className="text-xs px-2.5 py-1 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-mono">
              v0.1.0-devsecops
            </span>
            <span className="text-xs text-gray-400 hidden sm:inline">
              Continuous Application Security Testing
            </span>
          </div>

          <div className="flex items-center gap-4 text-xs">
            <a
              href="/api/health"
              target="_blank"
              rel="noreferrer"
              className="text-gray-400 hover:text-gray-200 flex items-center gap-1"
            >
              API Health
              <ExternalLink className="w-3 h-3" />
            </a>
            <a
              href="/api/docs"
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-200 transition-colors flex items-center gap-1 border border-gray-700"
            >
              API Docs
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </header>

        {/* Content View */}
        <main className="flex-1">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/projects" element={<Projects />} />
            <Route path="/projects/:id" element={<ProjectDetail />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default App;
