
import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Upload,
  Search,
  Sparkles,
  Activity,
  FileText,
  FileSpreadsheet,
  Globe,
} from 'lucide-react';
import {
  Project,
  Finding,
  Scan,
  projectsApi,
  findingsApi,
  scansApi,
  reportsApi,
} from '../api/client';
import api from '../api/client';
import { SeverityBadge } from '../components/SeverityBadge';
import { GateBadge } from '../components/GateBadge';
import { AIRemediationModal } from '../components/AIRemediationModal';
import { UploadScanModal } from '../components/UploadScanModal';

const ALL_SCANS = 'all';

export const ProjectDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  const [project, setProject] = useState<Project | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScanId, setSelectedScanId] = useState(ALL_SCANS);
  const [loading, setLoading] = useState(true);

  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [exporting, setExporting] = useState<'json' | 'csv' | 'pdf' | null>(null);

  const loadData = async (preferredScanId?: string) => {
    if (!id) {
      setLoading(false);
      return;
    }

    try {
      const [projData, scansData] = await Promise.all([
        projectsApi.get(id),
        scansApi.listByProject(id),
      ]);

      const nextScanId =
        preferredScanId && scansData.some((scan) => scan.id === preferredScanId)
          ? preferredScanId
          : scansData[0]?.id || ALL_SCANS;
      const findingsData = await findingsApi.listByProject(
        id,
        nextScanId === ALL_SCANS ? undefined : { scan_id: nextScanId }
      );

      setProject(projData);
      setScans(scansData);
      setSelectedScanId(nextScanId);
      setFindings(findingsData);
    } catch (err) {
      console.error('Failed to load project details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, [id]);

  const handleScanSelection = async (scanId: string) => {
    if (!id) return;
    setSelectedScanId(scanId);
    try {
      const nextFindings = await findingsApi.listByProject(
        id,
        scanId === ALL_SCANS ? undefined : { scan_id: scanId }
      );
      setFindings(nextFindings);
    } catch (err) {
      console.error('Failed to load scan findings:', err);
    }
  };

  const handleStatusUpdated = (updatedFinding: Finding) => {
    setSelectedFinding(updatedFinding);

    setFindings((prev) =>
      prev.map((finding) =>
        finding.id === updatedFinding.id ? updatedFinding : finding
      )
    );

    if (id) {
      projectsApi
        .get(id)
        .then((updatedProject) => setProject(updatedProject))
        .catch((error) =>
          console.error('Failed to refresh project:', error)
        );
    }
  };

  const downloadReport = async (
    scanId: string,
    format: 'json' | 'csv' | 'pdf'
  ) => {
    setExporting(format);

    try {
      const reportPath =
        format === 'json'
          ? reportsApi.getJsonExportUrl(scanId)
          : format === 'csv'
            ? reportsApi.getCsvExportUrl(scanId)
            : reportsApi.getPdfExportUrl(scanId);

      // reportsApi returns a full /api/v1/... path.
      // The Axios instance already has /api/v1 as its baseURL.
      const endpoint = reportPath.replace(/^\/api\/v1/, '');

      const response = await api.get(endpoint, {
        responseType: 'blob',
      });

      const contentType =
        format === 'json'
          ? 'application/json'
          : format === 'csv'
            ? 'text/csv;charset=utf-8'
            : 'application/pdf';

      const blob = new Blob([response.data], { type: contentType });
      const objectUrl = window.URL.createObjectURL(blob);

      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = `scan-report-${scanId}.${format}`;

      document.body.appendChild(link);
      link.click();
      link.remove();

      window.URL.revokeObjectURL(objectUrl);
    } catch (error) {
      console.error(`${format.toUpperCase()} report export failed:`, error);
      alert(
        `${format.toUpperCase()} export failed. Please check your login and try again.`
      );
    } finally {
      setExporting(null);
    }
  };

  const filteredFindings = findings.filter((finding) => {
    const query = search.toLowerCase();

    const matchesSearch =
      !query ||
      finding.title.toLowerCase().includes(query) ||
      finding.rule_id.toLowerCase().includes(query) ||
      (finding.file_path &&
        finding.file_path.toLowerCase().includes(query)) ||
      (finding.endpoint &&
        finding.endpoint.toLowerCase().includes(query));

    const matchesSeverity =
      !severityFilter || finding.severity === severityFilter;
    const matchesCategory =
      !categoryFilter || finding.category === categoryFilter;
    const matchesStatus =
      !statusFilter || finding.status === statusFilter;

    return (
      matchesSearch &&
      matchesSeverity &&
      matchesCategory &&
      matchesStatus
    );
  });

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[60vh] text-gray-400">
        <Activity className="w-6 h-6 animate-spin mr-2 text-indigo-500" />
        Loading Project Overview...
      </div>
    );
  }

  if (!project) {
    return (
      <div className="p-8 text-center text-gray-400">
        <h2 className="text-base font-semibold text-white">
          Project Not Found
        </h2>
        <Link
          to="/projects"
          className="text-xs text-indigo-400 mt-2 inline-block"
        >
          &larr; Back to Projects
        </Link>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Top Bar Navigation */}
      <div className="flex items-center gap-2 text-xs text-gray-400">
        <Link
          to="/projects"
          className="hover:text-gray-200 flex items-center gap-1"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Projects
        </Link>
        <span>/</span>
        <span className="text-gray-200 font-medium">{project.name}</span>
      </div>

      {/* Project Banner & Actions */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            {project.name}
          </h1>

          <p className="text-xs text-gray-400 mt-1 max-w-2xl">
            {project.description || 'Target security scanning repository'}
          </p>

          {project.target_url && (
            <div className="flex items-center gap-2 text-xs text-indigo-400 mt-2 font-mono">
              <Globe className="w-3.5 h-3.5 text-gray-400" />
              <a
                href={project.target_url}
                target="_blank"
                rel="noreferrer"
                className="hover:underline"
              >
                {project.target_url}
              </a>
            </div>
          )}
        </div>

        <div className="flex items-center flex-wrap gap-2.5">
          {scans.length > 0 && (
            <>
              <button
                type="button"
                onClick={() => void downloadReport(scans[0].id, 'json')}
                disabled={exporting !== null}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-300 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors border border-gray-700"
              >
                <FileText className="w-3.5 h-3.5" />
                {exporting === 'json' ? 'Exporting JSON...' : 'Export JSON'}
              </button>

              <button
                type="button"
                onClick={() => void downloadReport(scans[0].id, 'csv')}
                disabled={exporting !== null}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-300 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors border border-gray-700"
              >
                <FileSpreadsheet className="w-3.5 h-3.5" />
                {exporting === 'csv' ? 'Exporting CSV...' : 'Export CSV'}
              </button>

              <button
                type="button"
                onClick={() => void downloadReport(scans[0].id, 'pdf')}
                disabled={exporting !== null}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-300 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors border border-gray-700"
              >
                <FileText className="w-3.5 h-3.5" />
                {exporting === 'pdf' ? 'Exporting PDF...' : 'Export PDF'}
              </button>
            </>
          )}

          <button
            type="button"
            onClick={() => setIsScanModalOpen(true)}
            className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-medium flex items-center gap-1.5 shadow-lg shadow-indigo-600/20 transition-colors"
          >
            <Upload className="w-3.5 h-3.5" />
            Scan Codebase
          </button>
        </div>
      </div>

      {/* Historical Scans */}
      {scans.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-gray-800 flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-300">
              Scan Pipeline History ({scans.length})
            </h2>
            <span className="text-[10px] text-gray-500">
              Latest scan results
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-gray-950/40 text-gray-400 uppercase tracking-wider font-medium text-[10px] border-b border-gray-800">
                <tr>
                  <th className="py-2.5 px-4">Scan ID</th>
                  <th className="py-2.5 px-4">Scope</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Security Gate</th>
                  <th className="py-2.5 px-4">Findings Breakdown</th>
                  <th className="py-2.5 px-4">Executed At</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-gray-800/60 font-mono text-xs">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-gray-800/30">
                    <td className="py-2.5 px-4 text-indigo-400">
                      {scan.id.slice(0, 8)}...
                    </td>
                    <td className="py-2.5 px-4 uppercase">
                      {scan.scan_type}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="text-emerald-400">
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      <GateBadge
                        status={scan.gate_status}
                        reason={scan.gate_reason}
                      />
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="text-red-400 font-bold">
                        {scan.critical_count}C
                      </span>{' '}
                      <span className="text-orange-400 font-bold">
                        {scan.high_count}H
                      </span>{' '}
                      <span className="text-amber-400">
                        {scan.medium_count}M
                      </span>{' '}
                      <span className="text-blue-400">
                        {scan.low_count}L
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-gray-500">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Findings Section */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold text-white tracking-tight">
              Vulnerability Findings
            </h2>
            <p className="text-xs text-gray-400">
              Findings are shown for the selected scan; choose all scans to review history.
            </p>
          </div>
          <label className="flex items-center gap-2 text-xs text-gray-400">
            Scan
            <select
              value={selectedScanId}
              onChange={(event) => void handleScanSelection(event.target.value)}
              className="max-w-xs bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
            >
              <option value={ALL_SCANS}>All scans (historical)</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.created_at ? new Date(scan.created_at).toLocaleString() : scan.id} — {scan.scan_type} — {scan.target_label || scan.id.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
        </div>

        {/* Filters Bar */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="w-3.5 h-3.5 text-gray-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search findings by title, rule ID, or file..."
              className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-indigo-500"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={categoryFilter}
            onChange={(event) => setCategoryFilter(event.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="">All Vectors</option>
            <option value="sast">SAST (Semgrep)</option>
            <option value="secret">Secret Detection</option>
            <option value="sca">SCA (Dependencies)</option>
            <option value="dast">DAST (Dynamic)</option>
          </select>

          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="fixed">Fixed</option>
            <option value="retested">Retested</option>
            <option value="closed">Closed</option>
          </select>
        </div>

        {/* Findings Table */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-gray-950/50 text-gray-400 uppercase tracking-wider font-medium text-[10px] border-b border-gray-800">
                <tr>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Title &amp; Description</th>
                  <th className="py-3 px-4">Vector / Scanner</th>
                  <th className="py-3 px-4">Location</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-gray-800/60">
                {filteredFindings.length > 0 ? (
                  filteredFindings.map((finding) => (
                    <tr
                      key={finding.id}
                      className="hover:bg-gray-800/30 transition-colors"
                    >
                      <td className="py-3 px-4">
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="py-3 px-4 max-w-sm">
                        <div className="font-semibold text-white truncate">
                          {finding.title}
                        </div>
                        <div className="text-[11px] text-gray-400 truncate mt-0.5">
                          {finding.description}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="uppercase font-mono text-[10px] text-indigo-400 font-medium">
                          {finding.category}
                        </div>
                        <div className="text-[10px] text-gray-500 font-mono">
                          {finding.scanner}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-gray-300 max-w-[200px] truncate">
                        {finding.file_path ? (
                          <span>
                            {finding.file_path}
                            {finding.line_number
                              ? `:${finding.line_number}`
                              : ''}
                          </span>
                        ) : finding.endpoint ? (
                          <span>{finding.endpoint}</span>
                        ) : finding.package_name ? (
                          <span>
                            {finding.package_name}@{finding.package_version}
                          </span>
                        ) : (
                          'N/A'
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono font-bold text-white">
                        {finding.risk_score}
                        <span className="text-gray-500 font-normal">/10</span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-medium uppercase font-mono ${
                            finding.status === 'fixed'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                              : finding.status === 'in_progress'
                                ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/30'
                                : 'bg-gray-800 text-gray-300'
                          }`}
                        >
                          {finding.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          type="button"
                          onClick={() => setSelectedFinding(finding)}
                          className="px-3 py-1 bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 rounded text-xs font-medium inline-flex items-center gap-1.5 transition-colors"
                        >
                          <Sparkles className="w-3 h-3 text-amber-400" />
                          Remediation
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-gray-500">
                      No findings match the current filter criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* AI Remediation Modal */}
      {selectedFinding && (
        <AIRemediationModal
          key={selectedFinding.id}
          finding={selectedFinding}
          isOpen={!!selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusUpdated={handleStatusUpdated}
        />
      )}

      {/* Upload & Scan Modal */}
      {isScanModalOpen && (
        <UploadScanModal
          projectId={project.id}
          projectTargetUrl={project.target_url}
          isOpen={isScanModalOpen}
          onClose={() => setIsScanModalOpen(false)}
          onSuccess={(scanId) => void loadData(scanId)}
        />
      )}
    </div>
  );
};

export default ProjectDetail;
