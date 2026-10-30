import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  FolderGit2,
  Activity,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import { reportsApi, Metrics } from '../api/client';
import { GateBadge } from '../components/GateBadge';

export const Dashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchMetrics = async (isBackground = false) => {
    if (!isBackground) setLoading(true);
    setRefreshing(true);
    try {
      const data = await reportsApi.getMetrics();
      setMetrics(data);
    } catch (err) {
      console.error('Failed to load dashboard metrics', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchMetrics();

    // Listen for cross-component lifecycle updates to keep metrics in sync
    const handleInvalidate = () => {
      fetchMetrics(true);
    };
    window.addEventListener('devsecops:metrics-invalidated', handleInvalidate);
    return () => {
      window.removeEventListener('devsecops:metrics-invalidated', handleInvalidate);
    };
  }, []);

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[60vh] text-gray-400">
        <Activity className="w-6 h-6 animate-spin mr-2 text-indigo-500" />
        Loading Security Dashboard...
      </div>
    );
  }

  const sevData = [
    { name: 'Critical', value: metrics?.severity_counts.critical || 0, color: '#ef4444' },
    { name: 'High', value: metrics?.severity_counts.high || 0, color: '#f97316' },
    { name: 'Medium', value: metrics?.severity_counts.medium || 0, color: '#f59e0b' },
    { name: 'Low', value: metrics?.severity_counts.low || 0, color: '#3b82f6' },
  ].filter((d) => d.value > 0);

  const categoryData = Object.entries(metrics?.category_counts || {}).map(([key, val]) => ({
    category: key.toUpperCase(),
    findings: val,
  }));

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Operations Dashboard</h1>
          <p className="text-sm text-gray-400 mt-1">
            Real-time vulnerability metrics, multi-scanner signals, and CI/CD gate status
          </p>
          <p className="text-xs text-gray-500 mt-1">
            Overview counts include findings from scan history. Open a project to review a specific scan; historical evidence is retained after rescans.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchMetrics()}
            disabled={refreshing}
            className="px-3 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm font-medium flex items-center gap-2 border border-gray-700 transition-colors disabled:opacity-50"
            title="Refresh Security Metrics"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-indigo-400' : ''}`} />
            Refresh
          </button>
          <Link
            to="/projects"
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium flex items-center gap-2 shadow-lg shadow-indigo-600/20 transition-colors"
          >
            View Projects
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="bg-gray-900 border border-gray-800 p-5 rounded-xl">
          <div className="flex items-center justify-between text-gray-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">Active Projects</span>
            <FolderGit2 className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="text-3xl font-bold text-white">{metrics?.total_projects || 0}</div>
          <div className="text-xs text-gray-500 mt-1">Repositories monitored</div>
        </div>

        <div className="bg-gray-900 border border-gray-800 p-5 rounded-xl">
          <div className="flex items-center justify-between text-gray-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Scans</span>
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold text-white">{metrics?.total_scans || 0}</div>
          <div className="text-xs text-gray-500 mt-1">SAST, Secret, SCA, DAST</div>
        </div>

        <div className="bg-gray-900 border border-gray-800 p-5 rounded-xl">
          <div className="flex items-center justify-between text-gray-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">Critical & High</span>
            <ShieldAlert className="w-5 h-5 text-red-400" />
          </div>
          <div className="text-3xl font-bold text-red-400">
            {(metrics?.severity_counts.critical || 0) + (metrics?.severity_counts.high || 0)}
          </div>
          <div className="text-xs text-red-500/80 mt-1">Open findings across scan history</div>
        </div>

        <div className="bg-gray-900 border border-gray-800 p-5 rounded-xl">
          <div className="flex items-center justify-between text-gray-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">Security Gate Pass Rate</span>
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="text-3xl font-bold text-emerald-400">
            {metrics?.total_scans
              ? `${Math.round(
                  ((metrics.gate_status_counts.passed || 0) / metrics.total_scans) * 100
                )}%`
              : '100%'}
          </div>
          <div className="text-xs text-gray-500 mt-1">
            {metrics?.gate_status_counts.passed || 0} passed / {metrics?.gate_status_counts.failed || 0} blocked
          </div>
        </div>
      </div>

      {/* Visual Analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="bg-gray-900 border border-gray-800 p-6 rounded-xl">
          <h2 className="text-sm font-semibold text-white mb-4">Vulnerability Severity Breakdown</h2>
          {sevData.length > 0 ? (
            <div className="h-64 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={sevData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={85}
                    paddingAngle={4}
                  >
                    {sevData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#374151' }}
                    itemStyle={{ color: '#e5e7eb' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-col gap-2 pl-4">
                {sevData.map((d) => (
                  <div key={d.name} className="flex items-center gap-2 text-xs">
                    <span className="w-3 h-3 rounded-full" style={{ backgroundColor: d.color }} />
                    <span className="text-gray-400">{d.name}:</span>
                    <span className="font-semibold text-white">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-xs text-gray-500">
              No vulnerabilities detected yet. Launch a scan to visualize findings.
            </div>
          )}
        </div>

        {/* Vectors Bar Chart */}
        <div className="bg-gray-900 border border-gray-800 p-6 rounded-xl">
          <h2 className="text-sm font-semibold text-white mb-4">Findings by Security Vector</h2>
          {categoryData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryData}>
                  <XAxis dataKey="category" stroke="#9ca3af" fontSize={11} />
                  <YAxis stroke="#9ca3af" fontSize={11} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#374151' }}
                    itemStyle={{ color: '#e5e7eb' }}
                  />
                  <Bar dataKey="findings" fill="#6366f1" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-xs text-gray-500">
              No category data available.
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="p-5 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Recent Security Pipeline Activity</h2>
          <span className="text-xs text-gray-500">Latest pipeline executions</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-gray-300">
            <thead className="bg-gray-950/50 text-gray-400 uppercase tracking-wider font-medium text-[10px] border-b border-gray-800">
              <tr>
                <th className="py-3 px-4">Scan ID</th>
                <th className="py-3 px-4">Scope</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Gate Result</th>
                <th className="py-3 px-4">Severity Breakdown</th>
                <th className="py-3 px-4">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60 font-mono">
              {metrics?.recent_scans && metrics.recent_scans.length > 0 ? (
                metrics.recent_scans.map((s) => (
                  <tr key={s.id} className="hover:bg-gray-800/30 transition-colors">
                    <td className="py-3 px-4 text-indigo-400 font-medium">
                      <Link to={`/projects/${s.project_id}`}>{s.id.slice(0, 8)}...</Link>
                    </td>
                    <td className="py-3 px-4 uppercase text-gray-300">{s.scan_type}</td>
                    <td className="py-3 px-4">
                      <span className="text-emerald-400">{s.status}</span>
                    </td>
                    <td className="py-3 px-4">
                      <GateBadge status={s.gate_status} />
                    </td>
                    <td className="py-3 px-4 text-xs font-mono">
                      <span className="text-red-400 font-bold">{s.critical}C</span>{' '}
                      <span className="text-orange-400 font-bold">{s.high}H</span>{' '}
                      <span className="text-amber-400">{s.medium}M</span>{' '}
                      <span className="text-blue-400">{s.low}L</span>
                    </td>
                    <td className="py-3 px-4 text-gray-500">
                      {new Date(s.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-gray-500">
                    No scan runs recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
