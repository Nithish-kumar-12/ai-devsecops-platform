import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Clock } from 'lucide-react';

interface GateBadgeProps {
  status: string;
  reason?: string;
}

export const GateBadge: React.FC<GateBadgeProps> = ({ status, reason }) => {
  const s = (status || 'pending').toLowerCase();

  if (s === 'passed') {
    return (
      <span
        title={reason || 'Passed all gate thresholds'}
        className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
      >
        <ShieldCheck className="w-3.5 h-3.5" />
        PASSED
      </span>
    );
  }

  if (s === 'failed') {
    return (
      <span
        title={reason || 'Failed policy thresholds'}
        className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20"
      >
        <ShieldAlert className="w-3.5 h-3.5" />
        FAILED
      </span>
    );
  }

  if (s === 'warning') {
    return (
      <span
        title={reason}
        className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20"
      >
        <AlertTriangle className="w-3.5 h-3.5" />
        WARNING
      </span>
    );
  }

  return (
    <span
      className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium bg-gray-500/10 text-gray-400 border border-gray-500/20"
    >
      <Clock className="w-3.5 h-3.5" />
      PENDING
    </span>
  );
};
