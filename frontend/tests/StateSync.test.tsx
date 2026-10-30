import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import React, { useState } from 'react';
import { AIRemediationModal } from '../src/components/AIRemediationModal';
import { Finding, findingsApi } from '../src/api/client';

const mockFinding: Finding = {
  id: 'find-123',
  project_id: 'proj-1',
  scan_id: 'scan-1',
  rule_id: 'python.lang.security.audit.sqli',
  title: 'SQL Injection in Query Builder',
  description: 'Unsanitized user input formatted into SQL query string.',
  category: 'sast',
  severity: 'critical',
  file_path: 'app/database.py',
  line_number: 42,
  risk_score: 9.5,
  status: 'open',
  created_at: new Date().toISOString(),
};

describe('State Synchronization & AI Remediation', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('1. Generates AI remediation and immediately renders it without refreshing', async () => {
    const updatedFinding: Finding = {
      ...mockFinding,
      ai_analysis: 'Root Cause: User input directly interpolated into SQL query.',
      ai_fix_diff: '- query = f"SELECT * FROM users WHERE id = {user_id}"\n+ query = "SELECT * FROM users WHERE id = :user_id"',
      ai_verification_steps: 'Run automated pytest with SQL injection test vector payload.',
    };

    const generateAISpy = vi.spyOn(findingsApi, 'generateAI').mockResolvedValue(updatedFinding);
    const onStatusUpdated = vi.fn();
    const onClose = vi.fn();

    render(
      <AIRemediationModal
        finding={mockFinding}
        isOpen={true}
        onClose={onClose}
        onStatusUpdated={onStatusUpdated}
      />
    );

    const generateBtn = screen.getByRole('button', { name: /Generate AI Remediation/i });
    expect(generateBtn).toBeInTheDocument();
    expect(screen.queryByText(/Root Cause: User input directly interpolated/i)).not.toBeInTheDocument();

    fireEvent.click(generateBtn);

    expect(generateAISpy).toHaveBeenCalledWith('find-123');

    await waitFor(() => {
      expect(screen.getByText(/Root Cause: User input directly interpolated/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/Safe Code Diff/i)).toBeInTheDocument();
    expect(screen.getByText(/Developer Verification Steps/i)).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent(/generated and persisted successfully/i);
    expect(onStatusUpdated).toHaveBeenCalledWith(updatedFinding);
  });

  it('2. Changes Lifecycle State and immediately updates the UI without page reload', async () => {
    const updatedFinding: Finding = {
      ...mockFinding,
      status: 'fixed',
    };

    const updateStatusSpy = vi.spyOn(findingsApi, 'updateStatus').mockResolvedValue(updatedFinding);
    const onStatusUpdated = vi.fn();
    const onClose = vi.fn();

    render(
      <AIRemediationModal
        finding={mockFinding}
        isOpen={true}
        onClose={onClose}
        onStatusUpdated={onStatusUpdated}
      />
    );

    const select = screen.getByRole('combobox');
    expect(select).toHaveValue('open');

    fireEvent.change(select, { target: { value: 'fixed' } });

    expect(updateStatusSpy).toHaveBeenCalledWith('find-123', 'fixed');

    await waitFor(() => {
      expect(select).toHaveValue('fixed');
    });

    expect(screen.getByRole('status')).toHaveTextContent(/Lifecycle state updated to "fixed"/i);
    expect(onStatusUpdated).toHaveBeenCalledWith(updatedFinding);
  });

  it('3. Closes and reopens the finding; verifies the new data remains intact', async () => {
    // Harness component simulating ProjectDetail state management
    const TestContainer = () => {
      const [finding, setFinding] = useState<Finding>(mockFinding);
      const [modalOpen, setModalOpen] = useState(false);

      const handleUpdated = (updated: Finding) => {
        setFinding(updated);
      };

      return (
        <div>
          <button onClick={() => setModalOpen(true)}>Open Modal</button>
          <div data-testid="parent-status">{finding.status}</div>
          <div data-testid="parent-analysis">{finding.ai_analysis || 'none'}</div>

          {modalOpen && (
            <AIRemediationModal
              key={finding.id}
              finding={finding}
              isOpen={modalOpen}
              onClose={() => setModalOpen(false)}
              onStatusUpdated={handleUpdated}
            />
          )}
        </div>
      );
    };

    const updatedFinding: Finding = {
      ...mockFinding,
      status: 'fixed',
      ai_analysis: 'Persisted root-cause explanation for SQL injection.',
      ai_fix_diff: 'Use parameterized queries with SQLAlchemy text(:val)',
      ai_verification_steps: 'Verify with penetration test probe.',
    };

    vi.spyOn(findingsApi, 'updateStatus').mockResolvedValue(updatedFinding);

    render(<TestContainer />);

    expect(screen.getByTestId('parent-status')).toHaveTextContent('open');
    expect(screen.getByTestId('parent-analysis')).toHaveTextContent('none');

    // Open modal
    fireEvent.click(screen.getByRole('button', { name: /Open Modal/i }));

    // Change status to fixed
    const select = screen.getByRole('combobox');
    fireEvent.change(select, { target: { value: 'fixed' } });

    await waitFor(() => {
      expect(screen.getByTestId('parent-status')).toHaveTextContent('fixed');
    });

    // Close modal
    fireEvent.click(screen.getByRole('button', { name: /^Close$/i }));

    // Modal is closed
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();

    // Reopen modal
    fireEvent.click(screen.getByRole('button', { name: /Open Modal/i }));

    // Verify persisted state remains without browser refresh
    const reopenedSelect = screen.getByRole('combobox');
    expect(reopenedSelect).toHaveValue('fixed');
    expect(screen.getByTestId('parent-analysis')).toHaveTextContent(/Persisted root-cause explanation/i);
    expect(screen.getAllByText(/Persisted root-cause explanation/i).length).toBeGreaterThanOrEqual(1);
  });

  it('4. Handles AI generation API failure and shows an appropriate error banner', async () => {
    vi.spyOn(findingsApi, 'generateAI').mockRejectedValue({
      response: {
        data: {
          detail: 'AI service rate limit exceeded. Please wait 60 seconds.',
        },
      },
    });

    const onStatusUpdated = vi.fn();
    const onClose = vi.fn();

    render(
      <AIRemediationModal
        finding={mockFinding}
        isOpen={true}
        onClose={onClose}
        onStatusUpdated={onStatusUpdated}
      />
    );

    const generateBtn = screen.getByRole('button', { name: /Generate AI Remediation/i });
    fireEvent.click(generateBtn);

    await waitFor(() => {
      const alert = screen.getByRole('alert');
      expect(alert).toHaveTextContent(/AI service rate limit exceeded/i);
    });

    // Verify parent was NOT called with bad data
    expect(onStatusUpdated).not.toHaveBeenCalled();
  });

  it('5. Handles Lifecycle update API failure and shows an appropriate error banner', async () => {
    vi.spyOn(findingsApi, 'updateStatus').mockRejectedValue({
      response: {
        data: {
          detail: 'Database connection failed. Status change not saved.',
        },
      },
    });

    const onStatusUpdated = vi.fn();
    const onClose = vi.fn();

    render(
      <AIRemediationModal
        finding={mockFinding}
        isOpen={true}
        onClose={onClose}
        onStatusUpdated={onStatusUpdated}
      />
    );

    const select = screen.getByRole('combobox');
    fireEvent.change(select, { target: { value: 'fixed' } });

    await waitFor(() => {
      const alert = screen.getByRole('alert');
      expect(alert).toHaveTextContent(/Database connection failed/i);
    });

    expect(onStatusUpdated).not.toHaveBeenCalled();
  });

  it('6. Dispatches metrics invalidation event when status is updated', async () => {
    const updatedFinding: Finding = {
      ...mockFinding,
      status: 'in_progress',
    };

    vi.spyOn(findingsApi, 'updateStatus').mockResolvedValue(updatedFinding);

    let eventFired = false;
    const listener = () => {
      eventFired = true;
    };
    window.addEventListener('devsecops:metrics-invalidated', listener);

    render(
      <AIRemediationModal
        finding={mockFinding}
        isOpen={true}
        onClose={vi.fn()}
        onStatusUpdated={vi.fn()}
      />
    );

    const select = screen.getByRole('combobox');
    fireEvent.change(select, { target: { value: 'in_progress' } });

    await waitFor(() => {
      expect(eventFired).toBe(true);
    });

    window.removeEventListener('devsecops:metrics-invalidated', listener);
  });
});
