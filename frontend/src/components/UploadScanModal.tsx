import React, { useState, useRef } from 'react';
import {
  Upload, X, AlertCircle, FileArchive, Loader2, Globe, Shield, Code2, Lock,
} from 'lucide-react';
import { scansApi } from '../api/client';

// ─── 1 GiB limit (must match backend MAX_UPLOAD_SIZE_BYTES) ───────────────────
const MAX_UPLOAD_BYTES = 1_073_741_824;
const MAX_UPLOAD_LABEL = '1 GiB';

// Scan types that require a ZIP file
const CODE_SCAN_TYPES = new Set(['sast', 'secrets', 'sca', 'full']);
// Scan types that require a target URL
const DAST_SCAN_TYPES = new Set(['dast', 'full']);

interface UploadScanModalProps {
  projectId: string;
  projectTargetUrl?: string;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (scanId: string) => void;
}

export const UploadScanModal: React.FC<UploadScanModalProps> = ({
  projectId,
  projectTargetUrl,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [scanType, setScanType] = useState('full');
  const [confirmAuth, setConfirmAuth] = useState(false);
  const [targetUrl, setTargetUrl] = useState(projectTargetUrl || '');
  const [loading, setLoading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const isDastOnly = scanType === 'dast';
  const needsFile = CODE_SCAN_TYPES.has(scanType);
  const needsUrl = DAST_SCAN_TYPES.has(scanType);
  const isDastInvolved = needsUrl;

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0] || null;
    if (selected) {
      if (selected.size > MAX_UPLOAD_BYTES) {
        setError(
          `File is too large (${(selected.size / 1024 / 1024 / 1024).toFixed(2)} GiB). ` +
          `Maximum allowed size is ${MAX_UPLOAD_LABEL}. ` +
          `Exclude node_modules, .git, and build artifacts from your archive.`
        );
        setFile(null);
        if (fileInputRef.current) fileInputRef.current.value = '';
        return;
      }
      if (!selected.name.toLowerCase().endsWith('.zip')) {
        setError('Only .zip archives are accepted.');
        setFile(null);
        return;
      }
    }
    setFile(selected);
    setError(null);
  };

  const handleScanTypeChange = (newType: string) => {
    setScanType(newType);
    setError(null);
    // When switching to DAST-only, we no longer need the file
    if (newType === 'dast') {
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
    // When switching away from DAST-only, clear the confirmation so user has to re-confirm
    if (!DAST_SCAN_TYPES.has(newType)) {
      setConfirmAuth(false);
    }
  };

  const validate = (): string | null => {
    if (needsFile && !file) {
      return `A .zip source-code archive is required for '${scanType}' scans.`;
    }
    if (isDastInvolved && !confirmAuth) {
      return 'You must confirm target authorization before running a scan with DAST.';
    }
    if (isDastInvolved && !targetUrl.trim()) {
      return (
        'A target URL is required for DAST scanning. ' +
        (projectTargetUrl ? '' : 'Set a Target DAST URL on the project, or enter one below.')
      );
    }
    if (isDastInvolved && targetUrl.trim()) {
      try {
        const parsed = new URL(targetUrl.trim());
        if (!['http:', 'https:'].includes(parsed.protocol)) {
          return 'Target URL must use http:// or https://.';
        }
      } catch {
        return 'Target URL is not a valid URL (e.g. https://app.example.com).';
      }
    }
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);
    setError(null);
    setUploadProgress(0);

    const formData = new FormData();
    formData.append('project_id', projectId);
    formData.append('scan_type', scanType);
    formData.append('confirm_authorization', confirmAuth ? 'true' : 'false');

    if (targetUrl.trim() && isDastInvolved) {
      formData.append('target_url_override', targetUrl.trim());
    }

    if (file && needsFile) {
      formData.append('file', file);
    }

    try {
      const scan = await scansApi.uploadAndScan(formData, (progressEvent) => {
        if (progressEvent.total) {
          setUploadProgress(Math.round((progressEvent.loaded / progressEvent.total) * 100));
        }
      });
      onSuccess(scan.id);
      onClose();
    } catch (err: any) {
      const msg =
        err.response?.data?.detail ||
        err.message ||
        'Scan failed to execute. Check the backend logs for details.';
      setError(msg);
    } finally {
      setLoading(false);
      setUploadProgress(null);
    }
  };

  const scanTypeInfo: Record<string, { icon: React.ReactNode; label: string; hint: string }> = {
    full: {
      icon: <Shield className="w-3.5 h-3.5" />,
      label: 'Full DevSecOps (SAST + Secrets + SCA + DAST)',
      hint: 'Requires a .zip archive and a target URL.',
    },
    sast: {
      icon: <Code2 className="w-3.5 h-3.5" />,
      label: 'SAST Only – Semgrep static analysis',
      hint: 'Requires a .zip archive. No target URL needed.',
    },
    secrets: {
      icon: <Lock className="w-3.5 h-3.5" />,
      label: 'Secret Detection Only – Gitleaks',
      hint: 'Requires a .zip archive. No target URL needed.',
    },
    sca: {
      icon: <FileArchive className="w-3.5 h-3.5" />,
      label: 'SCA Only – OSV dependency scan',
      hint: 'Requires a .zip archive. No target URL needed.',
    },
    dast: {
      icon: <Globe className="w-3.5 h-3.5" />,
      label: 'DAST Only – Dynamic endpoint testing',
      hint: 'No archive needed. Requires a reachable target URL.',
    },
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-lg w-full p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-gray-200"
          aria-label="Close"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3 mb-5">
          <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/20 rounded-lg text-indigo-400">
            <Upload className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-white">Launch Security Scan</h2>
            <p className="text-xs text-gray-400">SAST · Secrets · SCA · DAST · Full Pipeline</p>
          </div>
        </div>

        {/* Error banner */}
        {error && (
          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-2.5 text-xs text-red-400">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* ── Scan Scope ─────────────────────────────────────────────────── */}
          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1.5">
              Scan Scope
            </label>
            <div className="grid gap-2">
              {Object.entries(scanTypeInfo).map(([value, info]) => (
                <label
                  key={value}
                  className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                    scanType === value
                      ? 'border-indigo-500/60 bg-indigo-500/10'
                      : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'
                  }`}
                >
                  <input
                    type="radio"
                    name="scanType"
                    value={value}
                    checked={scanType === value}
                    onChange={() => handleScanTypeChange(value)}
                    className="mt-0.5 accent-indigo-500"
                  />
                  <div>
                    <div className="flex items-center gap-1.5 text-xs font-medium text-gray-200">
                      <span className="text-indigo-400">{info.icon}</span>
                      {info.label}
                    </div>
                    <div className="text-[10px] text-gray-500 mt-0.5">{info.hint}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* ── File Upload (hidden when DAST-only) ────────────────────────── */}
          {needsFile && (
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1.5">
                Source Code ZIP Archive
                <span className="ml-1 text-gray-500 font-normal">(max {MAX_UPLOAD_LABEL})</span>
              </label>
              <div className="border-2 border-dashed border-gray-700 hover:border-indigo-500/50 rounded-lg p-5 text-center cursor-pointer transition-colors bg-gray-950/40 relative">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip"
                  onChange={handleFileChange}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  aria-label="Upload ZIP file"
                />
                <FileArchive className="w-8 h-8 text-gray-500 mx-auto mb-2" />
                {file ? (
                  <div className="text-xs text-indigo-400 font-medium">
                    {file.name}{' '}
                    <span className="text-gray-500 font-normal">
                      ({(file.size / (1024 * 1024)).toFixed(1)} MB)
                    </span>
                  </div>
                ) : (
                  <>
                    <p className="text-xs text-gray-300">Click to choose or drag &amp; drop .zip file</p>
                    <p className="text-[10px] text-gray-500 mt-1">
                      Protected against Zip Slip &amp; Archive Bombs · max {MAX_UPLOAD_LABEL}
                    </p>
                  </>
                )}
              </div>

              {/* Upload progress bar */}
              {uploadProgress !== null && (
                <div className="mt-2">
                  <div className="flex justify-between text-[10px] text-gray-400 mb-1">
                    <span>Uploading…</span>
                    <span>{uploadProgress}%</span>
                  </div>
                  <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-indigo-500 transition-all duration-200"
                      style={{ width: `${uploadProgress}%` }}
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Target URL (visible for DAST / Full) ───────────────────────── */}
          {needsUrl && (
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1.5">
                {isDastOnly ? 'Target URL *' : 'DAST Target URL *'}
              </label>
              <div className="relative">
                <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
                <input
                  type="url"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://app.example.com"
                  required={needsUrl}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 placeholder:text-gray-600"
                  aria-label="DAST target URL"
                />
              </div>
              {projectTargetUrl && (
                <p className="text-[10px] text-gray-500 mt-1">
                  Project default: <span className="text-indigo-400 font-mono">{projectTargetUrl}</span>
                  {!targetUrl && (
                    <button
                      type="button"
                      onClick={() => setTargetUrl(projectTargetUrl)}
                      className="ml-2 text-indigo-400 hover:text-indigo-300 underline"
                    >
                      Use
                    </button>
                  )}
                </p>
              )}
              {isDastOnly && (
                <p className="text-[10px] text-gray-500 mt-1.5 leading-relaxed">
                  ⚠ Ensure the target is a running web application you own or are authorized to test.
                  Local targets (127.0.0.1, localhost) are blocked by default unless{' '}
                  <code className="font-mono bg-gray-800 px-1 rounded">ALLOW_LOCAL_TARGETS=true</code> is set.
                </p>
              )}
            </div>
          )}

          {/* ── Authorization Checkbox ─────────────────────────────────────── */}
          {isDastInvolved && (
            <div className="p-3 bg-amber-500/5 border border-amber-500/20 rounded-lg">
              <label className="flex items-start gap-2.5 text-xs text-gray-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={confirmAuth}
                  onChange={(e) => setConfirmAuth(e.target.checked)}
                  className="mt-0.5 rounded border-gray-700 accent-indigo-500"
                  aria-label="Confirm DAST authorization"
                />
                <span>
                  I confirm that I own or am explicitly authorized to perform security testing
                  against this application target. Unauthorized testing is illegal.
                </span>
              </label>
            </div>
          )}

          {/* ── Submit ────────────────────────────────────────────────────── */}
          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-4 py-2 text-xs font-medium text-gray-400 hover:text-gray-200 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg flex items-center gap-2 disabled:opacity-50 transition-colors shadow-lg shadow-indigo-600/20"
              aria-label="Start scan"
            >
              {loading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  {uploadProgress !== null && uploadProgress < 100
                    ? `Uploading ${uploadProgress}%…`
                    : 'Running Security Pipeline…'}
                </>
              ) : (
                'Start Scan'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
