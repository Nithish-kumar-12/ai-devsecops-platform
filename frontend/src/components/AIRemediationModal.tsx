import React, { useState } from 'react';
import {
  X,
  Sparkles,
  Loader2,
  ShieldCheck,
  AlertCircle,
  CheckCircle2,
  RotateCw,
} from 'lucide-react';
import { Finding, findingsApi } from '../api/client';
import { SeverityBadge } from './SeverityBadge';

interface AIRemediationModalProps {
  finding: Finding | null;
  isOpen: boolean;
  onClose: () => void;
  onStatusUpdated: (updatedFinding: Finding) => void;
}

export const AIRemediationModal: React.FC<AIRemediationModalProps> = ({
  finding,
  isOpen,
  onClose,
  onStatusUpdated,
}) => {
  const [currentFinding, setCurrentFinding] = useState<Finding | null>(finding);
  const [loadingAI, setLoadingAI] = useState(false);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Synchronize state immutably whenever finding prop changes
  React.useEffect(() => {
    setCurrentFinding(finding);
    setError(null);
    setSuccessMessage(null);
  }, [finding]);

  if (!isOpen || !currentFinding) return null;

  const handleGenerateAI = async () => {
    if (!currentFinding) return;
    setLoadingAI(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const updated = await findingsApi.generateAI(currentFinding.id);
      // Immediately update local modal state and propagate up to parent
      setCurrentFinding(updated);
      onStatusUpdated(updated);
      setSuccessMessage('AI remediation guidance generated and persisted successfully.');
    } catch (err: any) {
      const msg =
        err?.response?.data?.detail ||
        err?.message ||
        'Failed to generate AI remediation guidance. Please try again.';
      setError(msg);
      console.error('Failed to generate AI remediation', err);
    } finally {
      setLoadingAI(false);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!currentFinding) return;
    setUpdatingStatus(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const updated = await findingsApi.updateStatus(currentFinding.id, newStatus);
      // Immediately update local modal state and propagate up to parent
      setCurrentFinding(updated);
      onStatusUpdated(updated);
      setSuccessMessage(`Lifecycle state updated to "${newStatus}".`);

      // Dispatch global event so dashboard and other listening components synchronize immediately
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('devsecops:metrics-invalidated'));
      }
    } catch (err: any) {
      const msg =
        err?.response?.data?.detail ||
        err?.message ||
        'Failed to update lifecycle status. Please try again.';
      setError(msg);
      console.error('Failed to update status', err);
    } finally {
      setUpdatingStatus(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm overflow-y-auto">
      <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-3xl w-full p-6 shadow-2xl relative my-8">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-gray-200 transition-colors"
          title="Close Modal"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="border-b border-gray-800 pb-4 mb-4">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <SeverityBadge severity={currentFinding.severity} />
            <span className="text-xs uppercase px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">
              {currentFinding.category}
            </span>
            <span className="text-xs text-gray-400 font-mono">
              Scanner: {currentFinding.scanner}
            </span>
            <span className="ml-auto text-xs font-mono text-indigo-400 font-semibold">
              Risk Score: {currentFinding.risk_score}/10
            </span>
          </div>
          <h2 className="text-base font-semibold text-white">{currentFinding.title}</h2>
          <p className="text-xs text-gray-400 mt-1">{currentFinding.description}</p>
        </div>

        {/* Notifications: Error & Success Banners */}
        {error && (
          <div
            role="alert"
            className="mb-4 p-3 bg-red-950/50 border border-red-800/80 text-red-200 rounded-lg text-xs flex items-center justify-between gap-3 shadow-md"
          >
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={() => setError(null)}
              className="text-red-400 hover:text-red-200 p-0.5 rounded"
              title="Dismiss error"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {successMessage && (
          <div
            role="status"
            className="mb-4 p-2.5 bg-emerald-950/40 border border-emerald-800 text-emerald-300 rounded-lg text-xs flex items-center justify-between gap-3 shadow-md"
          >
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <span>{successMessage}</span>
            </div>
            <button
              onClick={() => setSuccessMessage(null)}
              className="text-emerald-400 hover:text-emerald-200 p-0.5 rounded"
              title="Dismiss notification"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Location & Evidence */}
        <div className="grid grid-cols-1 gap-3 mb-4">
          <div className="bg-gray-950/60 p-3 rounded-lg border border-gray-800">
            <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider block mb-1">
              Location
            </span>
            <div className="text-xs font-mono text-gray-300">
              {currentFinding.file_path ? (
                <span>
                  {currentFinding.file_path}
                  {currentFinding.line_number ? ` (Line ${currentFinding.line_number})` : ''}
                </span>
              ) : currentFinding.endpoint ? (
                <span>{currentFinding.endpoint}</span>
              ) : currentFinding.package_name ? (
                <span>
                  {currentFinding.package_name}@{currentFinding.package_version}
                </span>
              ) : (
                'N/A'
              )}
            </div>
          </div>

          {currentFinding.evidence && (
            <div className="bg-gray-950/60 p-3 rounded-lg border border-gray-800">
              <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider block mb-1">
                Scanner Evidence
              </span>
              <pre className="text-xs font-mono text-emerald-400 overflow-x-auto whitespace-pre-wrap">
                {currentFinding.evidence}
              </pre>
            </div>
          )}

          {currentFinding.correlation_reason && (
            <div className="bg-indigo-950/20 p-3 rounded-lg border border-indigo-900/30 text-xs text-indigo-300 flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 text-indigo-400 flex-shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold block">Correlation Engine Insight:</span>
                <span>{currentFinding.correlation_reason}</span>
              </div>
            </div>
          )}
        </div>

        {/* AI Remediation Section */}
        <div className="border-t border-gray-800 pt-4 mb-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-amber-400">
                AI Remediation & Fix Guidance
              </h3>
            </div>
            <button
              onClick={handleGenerateAI}
              disabled={loadingAI}
              className="px-3 py-1 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              {loadingAI ? (
                <>
                  <Loader2 className="w-3 h-3 animate-spin" />
                  Generating Guidance...
                </>
              ) : currentFinding.ai_analysis ? (
                <>
                  <RotateCw className="w-3 h-3" />
                  Regenerate AI Fix
                </>
              ) : (
                <>
                  <Sparkles className="w-3 h-3" />
                  Generate AI Remediation
                </>
              )}
            </button>
          </div>

          {currentFinding.ai_analysis ? (
            <div className="space-y-3">
              <div className="bg-gray-950/80 p-3.5 rounded-lg border border-gray-800 text-xs text-gray-300 whitespace-pre-line leading-relaxed">
                {currentFinding.ai_analysis}
              </div>

              {currentFinding.ai_fix_diff && (
                <div className="bg-gray-950 p-3.5 rounded-lg border border-gray-800">
                  <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider block mb-1">
                    Safe Code Diff / Example
                  </span>
                  <pre className="text-xs font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap p-2 bg-black/40 rounded">
                    {currentFinding.ai_fix_diff}
                  </pre>
                </div>
              )}

              {currentFinding.ai_verification_steps && (
                <div className="bg-gray-950/80 p-3.5 rounded-lg border border-gray-800 text-xs text-gray-300 whitespace-pre-line leading-relaxed">
                  <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider block mb-1">
                    Developer Verification Steps
                  </span>
                  {currentFinding.ai_verification_steps}
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-950/30 border border-dashed border-gray-800 rounded-lg p-6 text-center">
              <p className="text-xs text-gray-400 mb-2">
                Click "Generate AI Remediation" to receive root-cause analysis, safe fix diff, and verification steps.
              </p>
            </div>
          )}
        </div>

        {/* Lifecycle Status Bar */}
        <div className="border-t border-gray-800 pt-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-400 font-medium">Lifecycle State:</span>
            <select
              value={currentFinding.status}
              disabled={updatingStatus}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="bg-gray-800 border border-gray-700 text-xs text-gray-200 rounded px-2.5 py-1.5 focus:outline-none focus:border-indigo-500 disabled:opacity-50"
            >
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="fixed">Fixed</option>
              <option value="retested">Retested</option>
              <option value="closed">Closed</option>
            </select>
            {updatingStatus && (
              <span className="text-[11px] text-gray-400 flex items-center gap-1 font-mono">
                <Loader2 className="w-3 h-3 animate-spin" /> Saving...
              </span>
            )}
          </div>

          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-medium bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
