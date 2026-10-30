import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  FolderGit2,
  Plus,
  Search,
  Upload,
  ExternalLink,
  Activity,
  Trash2,
  Loader2,
  X,
  Globe,
} from 'lucide-react';
import { Project, projectsApi } from '../api/client';
import { UploadScanModal } from '../components/UploadScanModal';

export const Projects: React.FC = () => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [activeScanProject, setActiveScanProject] = useState<Project | null>(null);

  // New Project Modal
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const fetchProjects = async () => {
    try {
      const data = await projectsApi.list();
      setProjects(data);
    } catch (err) {
      console.error('Failed to load projects', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    setCreating(true);
    setCreateError(null);
    try {
      await projectsApi.create({
        name,
        description,
        target_url: targetUrl || undefined,
      });
      setIsCreateOpen(false);
      setName('');
      setDescription('');
      setTargetUrl('');
      fetchProjects();
    } catch (err: any) {
      setCreateError(err.response?.data?.detail || 'Failed to create project');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!window.confirm(`Are you sure you want to delete project "${name}"? All scans and findings will be deleted.`)) {
      return;
    }
    try {
      await projectsApi.delete(id);
      fetchProjects();
    } catch (err) {
      console.error('Failed to delete project', err);
    }
  };

  const filtered = projects.filter(
    (p) =>
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      (p.description && p.description.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Projects</h1>
          <p className="text-sm text-gray-400 mt-1">
            Manage target repositories, source uploads, and configured policies
          </p>
        </div>
        <button
          onClick={() => setIsCreateOpen(true)}
          className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium flex items-center gap-2 shadow-lg shadow-indigo-600/20 transition-colors w-fit"
        >
          <Plus className="w-4 h-4" />
          New Project
        </button>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="w-4 h-4 text-gray-500 absolute left-3.5 top-3" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search projects by name or description..."
          className="w-full bg-gray-900 border border-gray-800 rounded-lg pl-10 pr-4 py-2.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-indigo-500"
        />
      </div>

      {/* Project Cards */}
      {loading ? (
        <div className="py-12 flex items-center justify-center text-gray-500 text-xs">
          <Activity className="w-4 h-4 animate-spin mr-2 text-indigo-500" />
          Loading Projects...
        </div>
      ) : filtered.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filtered.map((project) => (
            <div
              key={project.id}
              className="bg-gray-900 border border-gray-800 rounded-xl p-5 flex flex-col justify-between hover:border-gray-700 transition-colors group"
            >
              <div>
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 bg-indigo-500/10 border border-indigo-500/20 rounded-lg text-indigo-400">
                      <FolderGit2 className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-white group-hover:text-indigo-400 transition-colors">
                        <Link to={`/projects/${project.id}`}>{project.name}</Link>
                      </h3>
                      <p className="text-[10px] text-gray-500">
                        Created {new Date(project.created_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => handleDelete(project.id, project.name)}
                    title="Delete Project"
                    className="text-gray-500 hover:text-rose-400 p-1 rounded"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>

                <p className="text-xs text-gray-400 line-clamp-2 mt-2 mb-4">
                  {project.description || 'No description provided.'}
                </p>

                {project.target_url && (
                  <div className="flex items-center gap-1.5 text-[11px] text-gray-400 mb-3 truncate">
                    <Globe className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
                    <span className="truncate">{project.target_url}</span>
                  </div>
                )}

                {/* Vulnerability Pill Counters */}
                <div className="flex items-center gap-2 py-2 border-t border-gray-800/80 mb-4 text-xs font-mono">
                  <span className="text-gray-500">Open Findings:</span>
                  <span className="text-red-400 font-bold">{project.critical_count || 0}C</span>
                  <span className="text-orange-400 font-bold">{project.high_count || 0}H</span>
                  <span className="text-gray-400">({project.open_findings_count || 0} total)</span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 pt-2">
                <button
                  onClick={() => setActiveScanProject(project)}
                  className="flex-1 py-1.5 px-3 bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 rounded-lg text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
                >
                  <Upload className="w-3.5 h-3.5" />
                  Scan Code
                </button>
                <Link
                  to={`/projects/${project.id}`}
                  className="py-1.5 px-3 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg text-xs font-medium flex items-center justify-center gap-1 transition-colors"
                >
                  Details
                  <ExternalLink className="w-3 h-3" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-gray-900 border border-dashed border-gray-800 rounded-xl p-12 text-center">
          <FolderGit2 className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-white mb-1">No Projects Found</h3>
          <p className="text-xs text-gray-400 mb-4">
            Create your first security project or adjust your search filter.
          </p>
          <button
            onClick={() => setIsCreateOpen(true)}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-medium inline-flex items-center gap-1.5"
          >
            <Plus className="w-4 h-4" />
            Create Project
          </button>
        </div>
      )}

      {activeScanProject && (
        <UploadScanModal
          projectId={activeScanProject.id}
          projectTargetUrl={activeScanProject.target_url}
          isOpen={!!activeScanProject}
          onClose={() => setActiveScanProject(null)}
          onSuccess={() => fetchProjects()}
        />
      )}

      {/* Create Project Modal */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setIsCreateOpen(false)}
              className="absolute top-4 right-4 text-gray-400 hover:text-gray-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-semibold text-white mb-1">Create Security Project</h2>
            <p className="text-xs text-gray-400 mb-4">
              Set up a target application repository for continuous security auditing.
            </p>

            {createError && (
              <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
                {createError}
              </div>
            )}

            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1">Project Name *</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Payment Gateway Service"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1">Description</label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Brief description of application architecture or business role"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1">
                  Target DAST URL (Optional)
                </label>
                <input
                  type="url"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://app.example.com"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-4 py-2 text-xs font-medium text-gray-400 hover:text-gray-200 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg flex items-center gap-2 disabled:opacity-50"
                >
                  {creating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Create Project'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
