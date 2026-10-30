import React, { useState } from 'react';
import { Shield, Lock, Mail, User, AlertCircle, Loader2, KeyRound } from 'lucide-react';
import { authApi } from '../api/client';

interface LoginProps {
  onLoginSuccess: (token: string, user: any) => void;
}

export const Login: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (isRegister) {
        await authApi.register({
          email,
          password,
          full_name: fullName || undefined,
        });
        // Auto-login after registration
        const loginData = await authApi.login(email, password);
        localStorage.setItem('refresh_token', loginData.refresh_token);
        onLoginSuccess(loginData.access_token, loginData.user);
      } else {
        const loginData = await authApi.login(email, password);
        localStorage.setItem('refresh_token', loginData.refresh_token);
        onLoginSuccess(loginData.access_token, loginData.user);
      }
    } catch (err: any) {
      setError(
        err.response?.data?.detail || 'Authentication failed. Please verify credentials.'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleFillDemo = () => {
    setEmail('admin@example.com');
    setPassword('changeme');
    setError(null);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-gray-950 text-gray-100 relative overflow-hidden">
      {/* Background glow decoration */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="max-w-md w-full bg-gray-900 border border-gray-800 rounded-2xl p-8 shadow-2xl relative z-10">
        <div className="flex flex-col items-center mb-6">
          <div className="p-3 bg-indigo-500/10 border border-indigo-500/20 rounded-xl text-indigo-400 mb-3">
            <Shield className="w-8 h-8" />
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight">AI DevSecOps Platform</h1>
          <p className="text-xs text-gray-400 mt-1">
            Application Security Testing & Automated Gate Enforcement
          </p>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-800 mb-6">
          <button
            type="button"
            onClick={() => {
              setIsRegister(false);
              setError(null);
            }}
            className={`flex-1 py-2 text-xs font-semibold uppercase tracking-wider text-center border-b-2 transition-colors ${
              !isRegister
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setIsRegister(true);
              setError(null);
            }}
            className={`flex-1 py-2 text-xs font-semibold uppercase tracking-wider text-center border-b-2 transition-colors ${
              isRegister
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            Create Account
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-2 text-xs text-red-400">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegister && (
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1">Full Name</label>
              <div className="relative">
                <User className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Security Engineer"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">Email Address</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="developer@example.com"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold tracking-wide flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/20 transition-colors disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : isRegister ? (
              'Register Account'
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        {/* Demo Helper Button */}
        {!isRegister && (
          <div className="mt-6 pt-5 border-t border-gray-800 text-center">
            <button
              type="button"
              onClick={handleFillDemo}
              className="text-xs text-indigo-400 hover:text-indigo-300 inline-flex items-center gap-1.5 transition-colors font-medium"
            >
              <KeyRound className="w-3.5 h-3.5" />
              Autofill Admin Demo Credentials
            </button>
            <p className="text-[10px] text-gray-500 mt-1">Default: admin@example.com / changeme</p>
          </div>
        )}
      </div>
    </div>
  );
};
