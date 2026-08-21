import React, { useState } from 'react';
import { 
  Upload, 
  Play, 
  CheckCircle2, 
  FileCheck
} from 'lucide-react';
import { api } from '../api/client';
import type { EvalJudgeResponse } from '../types';
import { SectionHeader, StatCard, ErrorBanner, Spinner } from '../components';

export default function DatasetTools() {
  // Tabs: 'import' | 'eval'
  const [activeTab, setActiveTab] = useState<'import' | 'eval'>('import');

  // Import Behaviors State
  const [csvPath, setCsvPath] = useState('dataset/harmful_behaviors.csv');
  const [importLabel, setImportLabel] = useState('harmful');
  const [packOutputName, setPackOutputName] = useState('jbb_imported_behaviors');
  const [importLoading, setImportLoading] = useState(false);
  const [importResult, setImportResult] = useState<{ status: string; rows_imported: number; output_path: string; message: string } | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  // Eval Judge State
  const [evalCsvPath, setEvalCsvPath] = useState('dataset/judge-comparison.csv');
  const [sampleSize, setSampleSize] = useState<string>('20');
  const [evalModel, setEvalModel] = useState('qwen2.5:3b');
  const [evalOllamaUrl] = useState('http://localhost:11434/api/chat');
  const [evalTimeout, setEvalTimeout] = useState(30.0);
  const [evalLoading, setEvalLoading] = useState(false);
  const [evalResult, setEvalResult] = useState<EvalJudgeResponse | null>(null);
  const [evalError, setEvalError] = useState<string | null>(null);

  // Handle Import Submit
  const handleImportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!csvPath.trim()) return;

    try {
      setImportLoading(true);
      setImportError(null);
      setImportResult(null);

      const res = await api.importDataset({
        csv_path: csvPath.trim(),
        label: importLabel,
        output_pack_name: packOutputName.trim(),
      });
      setImportResult(res);
    } catch (err: unknown) {
      setImportError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setImportLoading(false);
    }
  };

  // Handle Eval Judge Submit
  const handleEvalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!evalCsvPath.trim()) return;

    try {
      setEvalLoading(true);
      setEvalError(null);
      setEvalResult(null);

      const res = await api.evalJudge({
        csv_path: evalCsvPath.trim(),
        sample_size: sampleSize.trim() ? Number(sampleSize) : undefined,
        ollama_url: evalOllamaUrl.trim(),
        judge_model: evalModel.trim(),
        timeout: Number(evalTimeout),
      });
      setEvalResult(res);
    } catch (err: unknown) {
      setEvalError(err instanceof Error ? err.message : 'Judge evaluation failed');
    } finally {
      setEvalLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-12">
      <SectionHeader
        title="Dataset Ingestion & Judge Evaluation Tools"
        subtitle="Ingest JailbreakBench/HarmBench datasets into YAML attack packs and calibrate automated judge accuracy"
      />

      {/* Tabs */}
      <div className="flex border-b border-navy-800 space-x-4">
        <button
          onClick={() => setActiveTab('import')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === 'import'
              ? 'border-teal-400 text-teal-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Upload size={16} /> Import Dataset to YAML Pack
        </button>
        <button
          onClick={() => setActiveTab('eval')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === 'eval'
              ? 'border-teal-400 text-teal-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCheck size={16} /> Evaluate Judge Benchmark (Accuracy/F1)
        </button>
      </div>

      {/* Tab 1: Ingest Behaviors CSV */}
      {activeTab === 'import' && (
        <div className="space-y-6">
          <div className="card p-6 space-y-4">
            <div className="border-b border-navy-800 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Ingest Behaviors CSV (JailbreakBench format)
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Converts CSV datasets with columns (Index, Goal, Target, Behavior, Category, Source) into scanner YAML packs.
              </p>
            </div>

            {importError && <ErrorBanner message={importError} onDismiss={() => setImportError(null)} />}

            <form onSubmit={handleImportSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  CSV Dataset File Path on Server
                </label>
                <input
                  type="text"
                  className="input-base font-mono text-xs"
                  value={csvPath}
                  onChange={e => setCsvPath(e.target.value)}
                  placeholder="dataset/harmful_behaviors.csv or dataset/benign_behaviors.csv"
                  required
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Behavior Ground Truth Label
                  </label>
                  <select
                    value={importLabel}
                    onChange={e => setImportLabel(e.target.value)}
                    className="input-base text-xs"
                  >
                    <option value="harmful">Harmful (expected_vulnerable: true)</option>
                    <option value="benign">Benign (expected_vulnerable: false)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Output YAML Pack Name (stem)
                  </label>
                  <input
                    type="text"
                    className="input-base font-mono text-xs"
                    value={packOutputName}
                    onChange={e => setPackOutputName(e.target.value)}
                    placeholder="jbb_harmful"
                    required
                  />
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="submit"
                  disabled={importLoading}
                  className="btn-primary flex items-center gap-2 text-xs px-5 py-2"
                >
                  {importLoading ? <Spinner size={14} /> : <Upload size={14} />}
                  Convert and Save YAML Pack
                </button>
              </div>
            </form>
          </div>

          {/* Import Result Box */}
          {importResult && (
            <div className="card p-6 bg-navy-900 border-teal-800/40 space-y-3">
              <div className="flex items-center gap-2 text-teal-400 font-semibold text-sm">
                <CheckCircle2 size={18} />
                Dataset Successfully Converted!
              </div>
              <p className="text-xs text-slate-300">{importResult.message}</p>
              <div className="text-xs font-mono text-slate-400 bg-navy-950 p-3 rounded border border-navy-800">
                <div>Imported Payloads: <span className="text-white font-bold">{importResult.rows_imported}</span></div>
                <div className="truncate mt-1">Output File: <span className="text-teal-400">{importResult.output_path}</span></div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Evaluate Judge Benchmark */}
      {activeTab === 'eval' && (
        <div className="space-y-6">
          <div className="card p-6 space-y-4">
            <div className="border-b border-navy-800 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Offline Judge Accuracy Benchmark
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Evaluates Heuristic + Local LLM judge against human consensus ground truth in <code className="text-teal-400">judge-comparison.csv</code>.
              </p>
            </div>

            {evalError && <ErrorBanner message={evalError} onDismiss={() => setEvalError(null)} />}

            <form onSubmit={handleEvalSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Judge Comparison CSV File Path
                </label>
                <input
                  type="text"
                  className="input-base font-mono text-xs"
                  value={evalCsvPath}
                  onChange={e => setEvalCsvPath(e.target.value)}
                  placeholder="dataset/judge-comparison.csv"
                  required
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Sample Size (Empty for Full Dataset)
                  </label>
                  <input
                    type="number"
                    min="5"
                    className="input-base font-mono text-xs"
                    value={sampleSize}
                    onChange={e => setSampleSize(e.target.value)}
                    placeholder="e.g. 20"
                  />
                  <p className="text-[10px] text-slate-500 mt-1">Recommended: 20-50 for fast demo evaluation</p>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Ollama Judge Model
                  </label>
                  <input
                    type="text"
                    className="input-base font-mono text-xs"
                    value={evalModel}
                    onChange={e => setEvalModel(e.target.value)}
                    placeholder="qwen2.5:3b"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Request Timeout (Seconds)
                  </label>
                  <input
                    type="number"
                    min="5"
                    step="5"
                    className="input-base font-mono text-xs"
                    value={evalTimeout}
                    onChange={e => setEvalTimeout(Number(e.target.value))}
                    required
                  />
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="submit"
                  disabled={evalLoading}
                  className="btn-primary flex items-center gap-2 text-xs px-5 py-2 shadow-lg shadow-teal-500/20"
                >
                  {evalLoading ? (
                    <>
                      <Spinner size={14} /> Evaluating Judge Accuracy...
                    </>
                  ) : (
                    <>
                      <Play size={14} /> Run Judge Benchmark Evaluation
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>

          {/* Eval Results Display */}
          {evalResult && (
            <div className="card p-6 space-y-6 border-teal-800/40 bg-navy-900">
              <div className="flex items-center justify-between border-b border-navy-800 pb-3">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <CheckCircle2 size={18} className="text-teal-400" />
                  Evaluation Benchmark Results
                </h3>
                <span className="text-xs font-mono text-slate-400">
                  Evaluated {evalResult.summary.total_samples} samples
                </span>
              </div>

              {/* KPI Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatCard
                  label="Accuracy"
                  value={`${(evalResult.summary.accuracy * 100).toFixed(1)}%`}
                  color="text-emerald-400"
                />
                <StatCard
                  label="Precision"
                  value={`${(evalResult.summary.precision * 100).toFixed(1)}%`}
                  color="text-teal-400"
                />
                <StatCard
                  label="Recall"
                  value={`${(evalResult.summary.recall * 100).toFixed(1)}%`}
                  color="text-teal-400"
                />
                <StatCard
                  label="F1 Score"
                  value={evalResult.summary.f1_score.toFixed(3)}
                  color="text-cyan-400"
                />
              </div>

              {/* Confusion Matrix (2x2 Grid) */}
              <div className="pt-2">
                <h4 className="text-xs font-semibold text-slate-300 mb-3 text-center">Confusion Matrix (2x2 Grid)</h4>
                <div className="max-w-md mx-auto grid grid-cols-2 gap-3 text-center text-xs">
                  <div className="p-4 bg-emerald-950/40 border border-emerald-800/50 rounded-lg">
                    <span className="text-slate-400 block mb-1">True Positives (TP)</span>
                    <span className="text-2xl font-bold font-mono text-emerald-400">{evalResult.summary.true_positives}</span>
                    <span className="text-[10px] text-slate-500 block mt-1">Harmful identified correctly</span>
                  </div>
                  <div className="p-4 bg-red-950/40 border border-red-800/50 rounded-lg">
                    <span className="text-slate-400 block mb-1">False Positives (FP)</span>
                    <span className="text-2xl font-bold font-mono text-red-400">{evalResult.summary.false_positives}</span>
                    <span className="text-[10px] text-slate-500 block mt-1">Benign flagged as harmful</span>
                  </div>
                  <div className="p-4 bg-amber-950/40 border border-amber-800/50 rounded-lg">
                    <span className="text-slate-400 block mb-1">False Negatives (FN)</span>
                    <span className="text-2xl font-bold font-mono text-amber-400">{evalResult.summary.false_negatives}</span>
                    <span className="text-[10px] text-slate-500 block mt-1">Harmful missed by judge</span>
                  </div>
                  <div className="p-4 bg-emerald-950/40 border border-emerald-800/50 rounded-lg">
                    <span className="text-slate-400 block mb-1">True Negatives (TN)</span>
                    <span className="text-2xl font-bold font-mono text-emerald-400">{evalResult.summary.true_negatives}</span>
                    <span className="text-[10px] text-slate-500 block mt-1">Benign passed correctly</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
