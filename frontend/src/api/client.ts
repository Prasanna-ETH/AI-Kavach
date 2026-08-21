// API client — thin wrappers over fetch. All calls go to /api (proxied by Vite).
import type { 
  Finding, 
  PayloadPackInfo, 
  ScanRequest, 
  ScanSummary,
  EvalJudgeResponse 
} from '../types';

const BASE = '/api';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      message = body.detail ?? message;
    } catch { /* ignore */ }
    throw new Error(message);
  }
  return res.json() as Promise<T>;
}

// ─── Scans ───────────────────────────────────────────────────────────────────

export const api = {
  // POST /api/scans → { scan_id, status, message }
  createScan: (req: ScanRequest) =>
    request<{ scan_id: string; status: string; message: string }>('/scans', {
      method: 'POST',
      body: JSON.stringify(req),
    }),

  // GET /api/scans
  listScans: () => request<ScanSummary[]>('/scans'),

  // GET /api/scans/:id
  getScan: (id: string) => request<ScanSummary>(`/scans/${id}`),

  // GET /api/scans/:id/findings
  getFindings: (
    id: string,
    filters?: {
      severity?: string;
      category?: string;
      judge_type?: string;
      vulnerable_only?: boolean;
      search?: string;
    }
  ) => {
    const params = new URLSearchParams();
    if (filters?.severity) params.set('severity', filters.severity);
    if (filters?.category) params.set('category', filters.category);
    if (filters?.judge_type) params.set('judge_type', filters.judge_type);
    if (filters?.vulnerable_only) params.set('vulnerable_only', 'true');
    if (filters?.search) params.set('search', filters.search);
    const qs = params.toString();
    return request<Finding[]>(`/scans/${id}/findings${qs ? `?${qs}` : ''}`);
  },

  // GET /api/payload-packs
  getPayloadPacks: () => request<PayloadPackInfo[]>('/payload-packs'),

  // POST /api/datasets/import
  importDataset: (body: {
    csv_path: string;
    label: string;
    output_pack_name: string;
  }) => request<{ status: string; rows_imported: number; output_path: string; message: string }>(
    '/datasets/import',
    { method: 'POST', body: JSON.stringify(body) }
  ),

  // POST /api/datasets/eval-judge
  evalJudge: (body: {
    csv_path: string;
    sample_size?: number;
    ollama_url: string;
    judge_model: string;
    timeout: number;
  }) => request<EvalJudgeResponse>('/datasets/eval-judge', {
    method: 'POST',
    body: JSON.stringify(body),
  }),

  // POST /api/scans/test-selectors
  testBrowserSelectors: (body: import('../types').BrowserTestSelectorsRequest) =>
    request<import('../types').BrowserTestSelectorsResponse>('/scans/test-selectors', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  // Report URLs (FileResponse — use anchor href)
  reportHtmlUrl: (id: string) => `/api/scans/${id}/report/html`,
  reportJsonUrl: (id: string) => `/api/scans/${id}/report/json`,
};

// ─── SSE hook helper ──────────────────────────────────────────────────────────

/**
 * Opens a Server-Sent Events connection to /api/scans/:id/stream.
 * Returns a cleanup function to close the EventSource.
 */
export function openScanStream(
  scanId: string,
  onEvent: (eventType: string, data: Record<string, unknown>) => void,
  onClose?: () => void
): () => void {
  const es = new EventSource(`/api/scans/${scanId}/stream`);

  es.onmessage = (e) => {
    try {
      const parsed = JSON.parse(e.data) as { event: string; data: Record<string, unknown> };
      onEvent(parsed.event, parsed.data);
      if (parsed.event === 'scan_complete' || parsed.event === 'scan_error') {
        es.close();
        onClose?.();
      }
    } catch { /* malformed JSON — skip */ }
  };

  es.onerror = () => {
    es.close();
    onClose?.();
  };

  return () => es.close();
}
