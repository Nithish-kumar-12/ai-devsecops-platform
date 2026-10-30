import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach JWT token from localStorage to outgoing requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor to handle 401 unauthorized
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (
      error.response?.status === 401
      && originalRequest
      && !originalRequest._retry
      && originalRequest.url !== '/auth/refresh'
    ) {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        originalRequest._retry = true;
        try {
          const refreshResponse = await api.post('/auth/refresh', {
            refresh_token: refreshToken,
          });
          const newToken = refreshResponse.data.access_token;
          const newRefreshToken = refreshResponse.data.refresh_token;
          localStorage.setItem('token', newToken);
          localStorage.setItem('refresh_token', newRefreshToken);
          originalRequest.headers = originalRequest.headers || {};
          originalRequest.headers.Authorization = `Bearer ${newToken}`;
          return api.request(originalRequest);
        } catch {
          localStorage.removeItem('token');
          localStorage.removeItem('refresh_token');
        }
      }

      if (window.location.pathname !== '/login') {
        window.location.assign('/login');
      }
    }
    return Promise.reject(error);
  }
);

export interface User {
  id: string;
  email: string;
  full_name?: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface Project {
  id: string;
  name: string;
  description?: string;
  owner_id: string;
  repository_url?: string;
  target_url?: string;
  default_branch: string;
  created_at: string;
  updated_at: string;
  total_scans?: number;
  open_findings_count?: number;
  critical_count?: number;
  high_count?: number;
}

export interface Finding {
  id: string;
  project_id: string;
  scan_id: string;
  scanner: string;
  rule_id: string;
  title: string;
  description: string;
  category: 'sast' | 'secret' | 'sca' | 'dast' | 'iac';
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: string;
  file_path?: string;
  line_number?: number;
  column_number?: number;
  endpoint?: string;
  param?: string;
  evidence?: string;
  package_name?: string;
  package_version?: string;
  fixed_version?: string;
  cve_id?: string;
  remediation?: string;
  ai_analysis?: string;
  ai_fix_diff?: string;
  ai_verification_steps?: string;
  status: 'open' | 'in_progress' | 'fixed' | 'retested' | 'closed';
  risk_score: number;
  correlation_group_id?: string;
  correlation_reason?: string;
  created_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  scan_type: string;
  status: string;
  source_type: string;
  target_label?: string;
  started_at?: string;
  completed_at?: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  gate_status: 'passed' | 'failed' | 'warning' | 'pending';
  gate_reason?: string;
  error_message?: string;
  scanner_details?: Record<string, any>;
  created_at: string;
  findings?: Finding[];
}

export interface Metrics {
  total_projects: number;
  total_scans: number;
  total_findings: number;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  category_counts: Record<string, number>;
  gate_status_counts: {
    passed: number;
    failed: number;
    pending: number;
  };
  recent_scans: Array<{
    id: string;
    project_id: string;
    scan_type: string;
    status: string;
    gate_status: string;
    created_at: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
}

export const authApi = {
  login: async (email: string, password: string) => {
    const res = await api.post('/auth/login', { email, password });
    return res.data;
  },
  register: async (payload: { email: string; password: string; full_name?: string; role?: string }) => {
    const res = await api.post('/auth/register', payload);
    return res.data;
  },
  getMe: async (): Promise<User> => {
    const res = await api.get('/auth/me');
    return res.data;
  },
};

export const projectsApi = {
  list: async (): Promise<Project[]> => {
    const res = await api.get('/projects');
    return res.data;
  },
  get: async (id: string): Promise<Project> => {
    const res = await api.get(`/projects/${id}`);
    return res.data;
  },
  create: async (payload: Partial<Project>): Promise<Project> => {
    const res = await api.post('/projects', payload);
    return res.data;
  },
  update: async (id: string, payload: Partial<Project>): Promise<Project> => {
    const res = await api.put(`/projects/${id}`, payload);
    return res.data;
  },
  delete: async (id: string) => {
    await api.delete(`/projects/${id}`);
  },
};

export const scansApi = {
  uploadAndScan: async (
    formData: FormData,
    onUploadProgress?: (progressEvent: { loaded: number; total?: number }) => void
  ): Promise<Scan> => {
    const res = await api.post('/scans/upload-and-scan', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      // 2-hour timeout for large archive uploads + long-running scan pipelines
      timeout: 7_200_000,
      onUploadProgress: onUploadProgress
        ? (evt) => onUploadProgress({ loaded: evt.loaded, total: evt.total })
        : undefined,
    });
    return res.data;
  },
  trigger: async (payload: {
    project_id: string;
    scan_type: string;
    source_type?: string;
    target_url?: string;
    confirm_authorization?: boolean;
  }): Promise<Scan> => {
    const res = await api.post('/scans/trigger', payload);
    return res.data;
  },
  getDetails: async (scanId: string): Promise<Scan> => {
    const res = await api.get(`/scans/${scanId}`);
    return res.data;
  },
  listByProject: async (projectId: string): Promise<Scan[]> => {
    const res = await api.get(`/scans/project/${projectId}`);
    return res.data;
  },
};

export const findingsApi = {
  listByProject: async (projectId: string, params?: Record<string, any>): Promise<Finding[]> => {
    const res = await api.get(`/findings/project/${projectId}`, { params });
    return res.data;
  },
  get: async (findingId: string): Promise<Finding> => {
    const res = await api.get(`/findings/${findingId}`);
    return res.data;
  },
  updateStatus: async (findingId: string, status: string): Promise<Finding> => {
    const res = await api.patch(`/findings/${findingId}/status`, { status });
    return res.data;
  },
  generateAI: async (findingId: string): Promise<Finding> => {
    const res = await api.post(`/findings/${findingId}/ai-remediation`);
    return res.data;
  },
};

export const reportsApi = {
  getMetrics: async (): Promise<Metrics> => {
    const res = await api.get('/reports/metrics');
    return res.data;
  },
  getJsonExportUrl: (scanId: string) => `/api/v1/reports/export/json/${scanId}`,
  getCsvExportUrl: (scanId: string) => `/api/v1/reports/export/csv/${scanId}`,
  getPdfExportUrl: (scanId: string) => `/api/v1/reports/export/pdf/${scanId}`,
};

export default api;
