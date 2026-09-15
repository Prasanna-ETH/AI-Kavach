import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Upload, 
  Play, 
  CheckCircle2, 
  FileCheck,
  FileText,
  ArrowRight,
  ArrowLeft,
  AlertTriangle,
  Code2,
  Sparkles,
  Layers,
  FileUp,
  ListFilter
} from 'lucide-react';
import { api } from '../api/client';
import type { 
  CommunityPreviewResponse, 
  CommunityConvertResponse, 
  CommunitySaveResponse,
  EvalJudgeResponse 
} from '../types';
import { SectionHeader, StatCard, ErrorBanner, Spinner } from '../components';

export default function DatasetTools() {
  const navigate = useNavigate();

  // Top Tabs: 'import' | 'eval'
  const [activeTab, setActiveTab] = useState<'import' | 'eval'>('import');

  // Import Sub-path Toggle: 'community' | 'jbb'
  const [importMode, setImportMode] = useState<'community' | 'jbb'>('community');

  // ───────────────────────────────────────────────────────────────────────────
  // 1. Existing JBB Importer State
  // ───────────────────────────────────────────────────────────────────────────
  const [csvPath, setCsvPath] = useState('dataset/harmful_behaviors.csv');
  const [importLabel, setImportLabel] = useState('harmful');
  const [packOutputName, setPackOutputName] = useState('jbb_imported_behaviors');
  const [importLoading, setImportLoading] = useState(false);
  const [importResult, setImportResult] = useState<{ status: string; rows_imported: number; output_path: string; message: string } | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  // ───────────────────────────────────────────────────────────────────────────
  // 2. Community Importer 4-Step Wizard State
  // ───────────────────────────────────────────────────────────────────────────
  const [wizardStep, setWizardStep] = useState<1 | 2 | 3 | 4>(1);

  // Step 1: Source
  const [sourceInputType, setSourceInputType] = useState<'file' | 'text'>('file');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [pastedText, setPastedText] = useState('');

  // Step 2: Preview & Mapping
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewData, setPreviewData] = useState<CommunityPreviewResponse | null>(null);
  const [fieldMapping, setFieldMapping] = useState<Record<string, string>>({});
  const [defaultCategory, setDefaultCategory] = useState('Community Payload Import');
  const [defaultOwaspId, setDefaultOwaspId] = useState('LLM01');
  const [defaultSeverity, setDefaultSeverity] = useState('HIGH');
  const [defaultExpectedVulnerable] = useState<boolean>(true);
  const [importCountOption, setImportCountOption] = useState<string>('ALL');
  const [customCount, setCustomCount] = useState<string>('500');

  // Step 3: YAML Preview
  const [convertLoading, setConvertLoading] = useState(false);
  const [convertData, setConvertData] = useState<CommunityConvertResponse | null>(null);

  // Step 4: Save
  const [packName, setPackName] = useState('');
  const [confirmedLargeImport, setConfirmedLargeImport] = useState(false);
  const [saveLoading, setSaveLoading] = useState(false);
  const [saveResult, setSaveResult] = useState<CommunitySaveResponse | null>(null);
  const [wizardError, setWizardError] = useState<string | null>(null);

  // ───────────────────────────────────────────────────────────────────────────
  // 3. Eval Judge State
  // ───────────────────────────────────────────────────────────────────────────
  const [evalCsvPath, setEvalCsvPath] = useState('dataset/judge-comparison.csv');
  const [sampleSize, setSampleSize] = useState<string>('20');
  const [evalModel, setEvalModel] = useState('qwen2.5:3b');
  const [evalOllamaUrl] = useState('http://localhost:11434/api/chat');
  const [evalTimeout, setEvalTimeout] = useState(30.0);
  const [evalLoading, setEvalLoading] = useState(false);
  const [evalResult, setEvalResult] = useState<EvalJudgeResponse | null>(null);
  const [evalError, setEvalError] = useState<string | null>(null);

  // ───────────────────────────────────────────────────────────────────────────
  // Handlers for JBB Importer
  // ───────────────────────────────────────────────────────────────────────────
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

  // ───────────────────────────────────────────────────────────────────────────
  // Handlers for Community Import 4-Step Wizard
  // ───────────────────────────────────────────────────────────────────────────

  // Step 1 -> Step 2: Preview & Detect
  const handleStep1Next = async () => {
    if (sourceInputType === 'file' && !selectedFile) {
      setWizardError('Please select a CSV, JSON, or TXT file to upload.');
      return;
    }
    if (sourceInputType === 'text' && !pastedText.trim()) {
      setWizardError('Please paste dataset text or raw prompts.');
      return;
    }

    try {
      setPreviewLoading(true);
      setWizardError(null);

      const res = await api.previewCommunityPayloads({
        file: sourceInputType === 'file' ? (selectedFile || undefined) : undefined,
        raw_text: sourceInputType === 'text' ? pastedText : undefined,
      });

      setPreviewData(res);
      setFieldMapping(res.suggested_mapping || {});

      // Suggest default pack name based on filename or timestamp
      let baseName = 'community_import';
      if (selectedFile) {
        baseName = selectedFile.name.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '_');
      }
      setPackName(baseName);
      setWizardStep(2);
    } catch (err: unknown) {
      setWizardError(err instanceof Error ? err.message : 'Failed to preview dataset');
    } finally {
      setPreviewLoading(false);
    }
  };

  // Step 2 -> Step 3: Convert to YAML
  const handleStep2Next = async () => {
    if (!previewData) return;
    if (previewData.detected_format !== 'txt' && !fieldMapping.prompt) {
      setWizardError('Prompt field mapping is required before proceeding.');
      return;
    }

    let maxRecs: number | undefined = undefined;
    if (importCountOption === 'ALL') {
      maxRecs = 0; // 0 = convert all
    } else if (importCountOption === 'custom') {
      maxRecs = customCount.trim() ? Number(customCount) : undefined;
    } else {
      maxRecs = Number(importCountOption);
    }

    try {
      setConvertLoading(true);
      setWizardError(null);

      const res = await api.convertCommunityPayloads({
        source_data: previewData.sample_rows.length > 0 ? previewData.sample_rows : [],
        raw_text: previewData.raw_text,
        max_records: maxRecs,
        detected_format: previewData.detected_format,
        field_mapping: fieldMapping,
        default_category: defaultCategory,
        default_owasp_id: defaultOwaspId,
        default_severity: defaultSeverity,
        default_expected_vulnerable: defaultExpectedVulnerable,
      });

      setConvertData(res);
      setWizardStep(3);
    } catch (err: unknown) {
      setWizardError(err instanceof Error ? err.message : 'Failed to convert dataset to YAML');
    } finally {
      setConvertLoading(false);
    }
  };

  // Step 3 -> Step 4: Proceed to Save
  const handleStep3Next = () => {
    setWizardError(null);
    setWizardStep(4);
  };

  // Step 4: Final Save
  const handleStep4Save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!convertData || !packName.trim()) return;

    if (convertData.total_count > 500 && !confirmedLargeImport) {
      setWizardError('This pack contains over 500 payloads. Please check the confirmation checkbox to save.');
      return;
    }

    try {
      setSaveLoading(true);
      setWizardError(null);

      const res = await api.saveCommunityPayloadPack({
        pack_name: packName.trim(),
        yaml_content: convertData.yaml_content,
        confirmed_large_import: confirmedLargeImport,
      });

      setSaveResult(res);
    } catch (err: unknown) {
      setWizardError(err instanceof Error ? err.message : 'Failed to save community payload pack');
    } finally {
      setSaveLoading(false);
    }
  };

  // Reset Wizard
  const resetWizard = () => {
    setWizardStep(1);
    setSelectedFile(null);
    setPastedText('');
    setPreviewData(null);
    setConvertData(null);
    setSaveResult(null);
    setWizardError(null);
    setConfirmedLargeImport(false);
  };

  // ───────────────────────────────────────────────────────────────────────────
  // Handlers for Eval Judge
  // ───────────────────────────────────────────────────────────────────────────
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
        subtitle="Ingest security datasets into YAML payload packs and calibrate automated LLM judge accuracy"
      />

      {/* Primary Navigation Tabs */}
      <div className="flex border-b border-navy-800 space-x-4">
        <button
          onClick={() => setActiveTab('import')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === 'import'
              ? 'border-teal-400 text-teal-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Upload size={16} /> Import Security Payloads to YAML Pack
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

      {/* TAB 1: PAYLOAD IMPORT */}
      {activeTab === 'import' && (
        <div className="space-y-6">
          {/* Sub-path Mode Switcher */}
          <div className="card p-4 flex flex-wrap items-center justify-between gap-4 bg-navy-900 border-navy-800">
            <div>
              <span className="text-xs font-bold text-white uppercase tracking-wider block">Import Method</span>
              <span className="text-xs text-slate-400">Choose between Community Any-Format Wizard and JailbreakBench CSV importer</span>
            </div>

            <div className="flex bg-navy-950 p-1 rounded-lg border border-navy-800">
              <button
                type="button"
                onClick={() => { setImportMode('community'); resetWizard(); }}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                  importMode === 'community'
                    ? 'bg-teal-500 text-navy-950 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Sparkles size={14} /> Community Import (Any Format)
              </button>
              <button
                type="button"
                onClick={() => setImportMode('jbb')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                  importMode === 'jbb'
                    ? 'bg-teal-500 text-navy-950 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers size={14} /> Known Format (JailbreakBench CSV)
              </button>
            </div>
          </div>

          {/* PATH A: COMMUNITY IMPORT 4-STEP WIZARD */}
          {importMode === 'community' && (
            <div className="space-y-6">
              {/* Wizard Progress Bar Header */}
              <div className="card p-4 bg-navy-900 border-navy-800">
                <div className="grid grid-cols-4 gap-2 text-center text-xs font-semibold">
                  <div className={`p-2.5 rounded border transition-colors flex items-center justify-center gap-2 ${
                    wizardStep === 1 ? 'border-teal-500 bg-teal-950/40 text-teal-400' : wizardStep > 1 ? 'border-teal-800 text-slate-300' : 'border-navy-800 text-slate-500'
                  }`}>
                    <span className="w-5 h-5 rounded-full bg-navy-950 border border-slate-700 flex items-center justify-center text-[10px]">1</span>
                    Step 1 — Source
                  </div>
                  <div className={`p-2.5 rounded border transition-colors flex items-center justify-center gap-2 ${
                    wizardStep === 2 ? 'border-teal-500 bg-teal-950/40 text-teal-400' : wizardStep > 2 ? 'border-teal-800 text-slate-300' : 'border-navy-800 text-slate-500'
                  }`}>
                    <span className="w-5 h-5 rounded-full bg-navy-950 border border-slate-700 flex items-center justify-center text-[10px]">2</span>
                    Step 2 — Mapping
                  </div>
                  <div className={`p-2.5 rounded border transition-colors flex items-center justify-center gap-2 ${
                    wizardStep === 3 ? 'border-teal-500 bg-teal-950/40 text-teal-400' : wizardStep > 3 ? 'border-teal-800 text-slate-300' : 'border-navy-800 text-slate-500'
                  }`}>
                    <span className="w-5 h-5 rounded-full bg-navy-950 border border-slate-700 flex items-center justify-center text-[10px]">3</span>
                    Step 3 — YAML Preview
                  </div>
                  <div className={`p-2.5 rounded border transition-colors flex items-center justify-center gap-2 ${
                    wizardStep === 4 ? 'border-teal-500 bg-teal-950/40 text-teal-400' : 'border-navy-800 text-slate-500'
                  }`}>
                    <span className="w-5 h-5 rounded-full bg-navy-950 border border-slate-700 flex items-center justify-center text-[10px]">4</span>
                    Step 4 — Save Pack
                  </div>
                </div>
              </div>

              {wizardError && <ErrorBanner message={wizardError} onDismiss={() => setWizardError(null)} />}

              {/* STEP 1: SOURCE SELECTION */}
              {wizardStep === 1 && (
                <div className="card p-6 space-y-5">
                  <div className="border-b border-navy-800 pb-3">
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                      <FileUp size={16} className="text-teal-400" />
                      Step 1: Provide Payload Source Data
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      Upload a CSV, JSON, or TXT file, or paste raw attack prompts directly. Format will be detected automatically.
                    </p>
                  </div>

                  <div className="flex gap-4">
                    <button
                      type="button"
                      onClick={() => setSourceInputType('file')}
                      className={`flex-1 p-3 rounded-lg border text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
                        sourceInputType === 'file'
                          ? 'border-teal-500 bg-teal-500/10 text-white'
                          : 'border-navy-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <Upload size={14} /> Upload File (.csv, .json, .txt)
                    </button>
                    <button
                      type="button"
                      onClick={() => setSourceInputType('text')}
                      className={`flex-1 p-3 rounded-lg border text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
                        sourceInputType === 'text'
                          ? 'border-teal-500 bg-teal-500/10 text-white'
                          : 'border-navy-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <FileText size={14} /> Paste Raw Text / Prompts
                    </button>
                  </div>

                  {sourceInputType === 'file' ? (
                    <div className="border-2 border-dashed border-navy-700 rounded-lg p-8 text-center bg-navy-950/40 hover:border-teal-500/60 transition-colors">
                      <Upload size={32} className="mx-auto text-teal-400 mb-3" />
                      <label className="block text-xs font-semibold text-slate-200 cursor-pointer mb-1">
                        Drag and drop your file here, or <span className="text-teal-400 underline">browse</span>
                        <input
                          type="file"
                          accept=".csv,.json,.txt"
                          onChange={e => setSelectedFile(e.target.files?.[0] || null)}
                          className="hidden"
                        />
                      </label>
                      <p className="text-[11px] text-slate-500">Supports .csv, .json (array of dicts or strings), and line-separated .txt files</p>

                      {selectedFile && (
                        <div className="mt-4 p-3 bg-navy-900 rounded inline-flex items-center gap-3 border border-teal-800/60 font-mono text-xs text-teal-300">
                          <CheckCircle2 size={16} className="text-teal-400" />
                          <span>{selectedFile.name}</span>
                          <span className="text-slate-400 text-[10px]">({(selectedFile.size / 1024).toFixed(1)} KB)</span>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                        Paste Raw Prompts or JSON/CSV Text
                      </label>
                      <textarea
                        className="input-base font-mono text-xs h-44"
                        value={pastedText}
                        onChange={e => setPastedText(e.target.value)}
                        placeholder="Paste newline-separated attack prompts, raw JSON array, or CSV text..."
                      />
                    </div>
                  )}

                  <div className="flex justify-end pt-2">
                    <button
                      type="button"
                      onClick={handleStep1Next}
                      disabled={previewLoading}
                      className="btn-primary flex items-center gap-2 text-xs px-5 py-2"
                    >
                      {previewLoading ? <Spinner size={14} /> : <ArrowRight size={14} />}
                      Next: Auto-Detect & Map Columns
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 2: PREVIEW & COLUMN MAPPING */}
              {wizardStep === 2 && previewData && (
                <div className="card p-6 space-y-6">
                  <div className="flex items-center justify-between border-b border-navy-800 pb-3">
                    <div>
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        <ListFilter size={16} className="text-teal-400" />
                        Step 2: Preview & Field Mapping
                      </h3>
                      <p className="text-xs text-slate-400 mt-1">
                        Detected format: <span className="text-teal-400 font-mono uppercase font-bold">{previewData.detected_format}</span> — Total records: <span className="text-white font-mono font-bold">{previewData.total_count}</span>
                      </p>
                    </div>

                    <button
                      type="button"
                      onClick={() => setWizardStep(1)}
                      className="btn-secondary text-xs flex items-center gap-1.5"
                    >
                      <ArrowLeft size={13} /> Change Source
                    </button>
                  </div>

                  {/* Sample Rows Table */}
                  <div className="space-y-2">
                    <span className="text-xs font-semibold text-slate-300">Sample Detected Rows (First 5)</span>
                    <div className="overflow-x-auto border border-navy-800 rounded bg-navy-950">
                      <table className="w-full text-left font-mono text-xs">
                        <thead className="bg-navy-900 text-slate-400 border-b border-navy-800">
                          <tr>
                            {previewData.columns?.map(col => (
                              <th key={col} className="p-2.5 font-semibold text-teal-400">{col}</th>
                            )) || <th className="p-2.5 text-teal-400">prompt</th>}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-navy-800/60 text-slate-300">
                          {previewData.sample_rows.map((row, idx) => (
                            <tr key={idx} className="hover:bg-navy-900/40">
                              {previewData.columns?.map(col => (
                                <td key={col} className="p-2.5 truncate max-w-xs">{String(row[col] ?? '')}</td>
                              )) || <td className="p-2.5 truncate max-w-md">{String(row.prompt ?? '')}</td>}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Column Mapping Form (if Tabular) */}
                  {previewData.detected_format !== 'txt' && (
                    <div className="p-4 bg-navy-950 rounded-lg border border-navy-800 space-y-4">
                      <span className="text-xs font-bold text-teal-400 uppercase tracking-wider block">
                        Column Mapping (Source Column → Scanner Payload Field)
                      </span>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label className="block text-xs font-semibold text-slate-300 mb-1">
                            Prompt Field Column <span className="text-red-400">*</span>
                          </label>
                          <select
                            value={fieldMapping.prompt || ''}
                            onChange={e => setFieldMapping(prev => ({ ...prev, prompt: e.target.value }))}
                            className="input-base text-xs font-mono"
                          >
                            <option value="">-- Select Source Column --</option>
                            {previewData.columns?.map(col => (
                              <option key={col} value={col}>{col}</option>
                            ))}
                          </select>
                        </div>

                        <div>
                          <label className="block text-xs font-semibold text-slate-300 mb-1">
                            Category Column (Optional)
                          </label>
                          <select
                            value={fieldMapping.category || ''}
                            onChange={e => setFieldMapping(prev => ({ ...prev, category: e.target.value }))}
                            className="input-base text-xs font-mono"
                          >
                            <option value="">-- Use Default Category Below --</option>
                            {previewData.columns?.map(col => (
                              <option key={col} value={col}>{col}</option>
                            ))}
                          </select>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Global Defaults Form */}
                  <div className="p-4 bg-navy-950 rounded-lg border border-navy-800 space-y-4">
                    <span className="text-xs font-bold text-slate-300 uppercase tracking-wider block">
                      Global Defaults for Entire Pack
                    </span>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1">Default Category</label>
                        <input
                          type="text"
                          className="input-base text-xs"
                          value={defaultCategory}
                          onChange={e => setDefaultCategory(e.target.value)}
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1">Default OWASP Category ID</label>
                        <select
                          value={defaultOwaspId}
                          onChange={e => setDefaultOwaspId(e.target.value)}
                          className="input-base text-xs font-mono"
                        >
                          <option value="LLM01">LLM01 — Prompt Injection</option>
                          <option value="LLM02">LLM02 — Sensitive Info Disclosure</option>
                          <option value="LLM06">LLM06 — Excessive Agency</option>
                          <option value="LLM07">LLM07 — System Prompt Leakage</option>
                          <option value="LLM08">LLM08 — Vector Weaknesses</option>
                          <option value="LLM09">LLM09 — Misinformation / Hallucination</option>
                        </select>
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1">Default Severity</label>
                        <select
                          value={defaultSeverity}
                          onChange={e => setDefaultSeverity(e.target.value)}
                          className="input-base text-xs"
                        >
                          <option value="CRITICAL">CRITICAL</option>
                          <option value="HIGH">HIGH</option>
                          <option value="MEDIUM">MEDIUM</option>
                          <option value="LOW">LOW</option>
                        </select>
                      </div>
                    </div>
                  </div>

                  {/* Payload Quantity / Import Limit Selector */}
                  <div className="p-4 bg-navy-950 rounded-lg border border-navy-800 space-y-3">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <span className="text-xs font-bold text-teal-400 uppercase tracking-wider block">
                        Import Payload Quantity & Limit
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        Source Total: <strong className="text-white font-bold">{previewData.total_count.toLocaleString()}</strong> payloads detected
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1">
                          Select How Many Payloads to Convert & Import
                        </label>
                        <select
                          value={importCountOption}
                          onChange={e => setImportCountOption(e.target.value)}
                          className="input-base text-xs font-mono"
                        >
                          <option value="ALL">Full Dataset — Convert All {previewData.total_count.toLocaleString()} Payloads</option>
                          <option value="50">First 50 Payloads (Quick Demo Pack)</option>
                          <option value="100">First 100 Payloads</option>
                          <option value="500">First 500 Payloads</option>
                          <option value="1000">First 1,000 Payloads</option>
                          <option value="5000">First 5,000 Payloads</option>
                          <option value="10000">First 10,000 Payloads</option>
                          <option value="custom">Custom Specified Amount...</option>
                        </select>
                      </div>

                      {importCountOption === 'custom' && (
                        <div>
                          <label className="block text-xs font-semibold text-slate-300 mb-1">
                            Custom Payload Limit Count
                          </label>
                          <input
                            type="number"
                            min="1"
                            max={previewData.total_count}
                            className="input-base text-xs font-mono"
                            value={customCount}
                            onChange={e => setCustomCount(e.target.value)}
                            placeholder="e.g. 250"
                          />
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex justify-between pt-2">
                    <button
                      type="button"
                      onClick={() => setWizardStep(1)}
                      className="btn-secondary text-xs"
                    >
                      Back
                    </button>
                    <button
                      type="button"
                      onClick={handleStep2Next}
                      disabled={convertLoading}
                      className="btn-primary flex items-center gap-2 text-xs px-5 py-2"
                    >
                      {convertLoading ? <Spinner size={14} /> : <Code2 size={14} />}
                      Next: Generate YAML Preview
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 3: YAML PREVIEW */}
              {wizardStep === 3 && convertData && (
                <div className="card p-6 space-y-6">
                  <div className="flex items-center justify-between border-b border-navy-800 pb-3">
                    <div>
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        <Code2 size={16} className="text-teal-400" />
                        Step 3: Generated YAML Preview
                      </h3>
                      <p className="text-xs text-slate-400 mt-1">
                        Converted <span className="text-white font-mono font-bold">{convertData.total_count.toLocaleString()}</span> security test vectors. Nothing written to disk yet.
                      </p>
                    </div>

                    <button
                      type="button"
                      onClick={() => setWizardStep(2)}
                      className="btn-secondary text-xs flex items-center gap-1.5"
                    >
                      <ArrowLeft size={13} /> Edit Mapping
                    </button>
                  </div>

                  {convertData.total_count > 500 && (
                    <div className="p-4 bg-amber-950/40 border border-amber-800/60 rounded-lg flex items-start gap-3 text-amber-300 text-xs">
                      <AlertTriangle size={18} className="shrink-0 text-amber-400 mt-0.5" />
                      <div>
                        <span className="font-bold">Large Batch Import Warning:</span> This dataset contains {convertData.total_count.toLocaleString()} payloads.
                        Importing &gt;500 payloads will require explicit confirmation in the next step.
                      </div>
                    </div>
                  )}

                  <div className="space-y-1">
                    <span className="text-xs font-mono text-slate-400">YAML Schema Preview (Sample Output):</span>
                    <pre className="p-4 bg-navy-950 rounded-lg border border-navy-800 font-mono text-xs text-teal-300 max-h-80 overflow-y-auto whitespace-pre">
                      {convertData.yaml_content.length > 5000
                        ? convertData.yaml_content.slice(0, 5000) + `\n\n# ... [${(convertData.total_count - 5).toLocaleString()} additional payloads included in full generated pack]`
                        : convertData.yaml_content}
                    </pre>
                  </div>

                  <div className="flex justify-between pt-2">
                    <button
                      type="button"
                      onClick={() => setWizardStep(2)}
                      className="btn-secondary text-xs"
                    >
                      Back
                    </button>
                    <button
                      type="button"
                      onClick={handleStep3Next}
                      className="btn-primary flex items-center gap-2 text-xs px-5 py-2"
                    >
                      Next: Save Payload Pack <ArrowRight size={14} />
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 4: SAVE PACK & DIRECT LINKS */}
              {wizardStep === 4 && (
                <div className="card p-6 space-y-6">
                  <div className="border-b border-navy-800 pb-3">
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                      <CheckCircle2 size={16} className="text-teal-400" />
                      Step 4: Name and Save Payload Pack
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      Final step: specify sanitized pack name. The YAML pack will be saved under <code className="text-teal-400">scanner/payloads/community/</code>.
                    </p>
                  </div>

                  {!saveResult ? (
                    <form onSubmit={handleStep4Save} className="space-y-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                          Payload Pack Name (Stem) <span className="text-red-400">*</span>
                        </label>
                        <input
                          type="text"
                          className="input-base font-mono text-xs"
                          value={packName}
                          onChange={e => setPackName(e.target.value)}
                          placeholder="custom_redteam_pack"
                          required
                        />
                        <p className="text-[11px] text-slate-500 mt-1">
                          Alphanumeric, underscores, and hyphens only. Saved as <code className="text-teal-400">community_{packName.toLowerCase().replace(/^community_/, '')}.yaml</code>
                        </p>
                      </div>

                      {convertData && convertData.total_count > 500 && (
                        <div className="p-3 bg-amber-950/30 border border-amber-800/50 rounded flex items-center gap-3 text-xs text-amber-200">
                          <input
                            type="checkbox"
                            id="confirmLarge"
                            checked={confirmedLargeImport}
                            onChange={e => setConfirmedLargeImport(e.target.checked)}
                            className="rounded border-amber-700 text-amber-500 focus:ring-amber-500"
                          />
                          <label htmlFor="confirmLarge" className="cursor-pointer font-semibold">
                            I confirm importing {convertData.total_count} payloads in a single pack batch.
                          </label>
                        </div>
                      )}

                      <div className="flex justify-between pt-2">
                        <button
                          type="button"
                          onClick={() => setWizardStep(3)}
                          className="btn-secondary text-xs"
                        >
                          Back
                        </button>
                        <button
                          type="submit"
                          disabled={saveLoading}
                          className="btn-primary flex items-center gap-2 text-xs px-6 py-2.5 shadow-lg shadow-teal-500/20"
                        >
                          {saveLoading ? <Spinner size={14} /> : <Upload size={14} />}
                          Save Payload Pack
                        </button>
                      </div>
                    </form>
                  ) : (
                    /* SUCCESS SCREEN WITH DIRECT LINKS */
                    <div className="space-y-6 bg-navy-900 p-6 rounded-lg border border-teal-800/50">
                      <div className="flex items-center gap-3 text-teal-400 font-bold text-base">
                        <CheckCircle2 size={24} />
                        Community Payload Pack Saved Successfully!
                      </div>
                      <p className="text-xs text-slate-300">{saveResult.message}</p>

                      <div className="text-xs font-mono text-slate-400 bg-navy-950 p-4 rounded border border-navy-800 space-y-1">
                        <div>Pack Name: <span className="text-white font-bold">{saveResult.pack_name}</span></div>
                        <div>Payload Count: <span className="text-teal-400 font-bold">{saveResult.count}</span></div>
                        <div className="truncate">File Path: <span className="text-slate-300">{saveResult.output_path}</span></div>
                      </div>

                      {/* Direct Navigation Shortcuts */}
                      <div className="flex flex-wrap gap-4 pt-2">
                        <button
                          type="button"
                          onClick={() => navigate('/payloads')}
                          className="btn-secondary text-xs flex items-center gap-2 px-4 py-2"
                        >
                          <FileText size={14} /> View in Payload Library
                        </button>

                        <button
                          type="button"
                          onClick={() => navigate(`/scan/new?pack=${saveResult.pack_name}`)}
                          className="btn-primary text-xs flex items-center gap-2 px-5 py-2 shadow-lg shadow-teal-500/20"
                        >
                          <Play size={14} /> Use in New Scan (Shortcut)
                        </button>

                        <button
                          type="button"
                          onClick={resetWizard}
                          className="text-xs text-slate-400 hover:text-white px-3 py-2 ml-auto"
                        >
                          Import Another Dataset
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* PATH B: EXISTING JAILBREAKBENCH CSV IMPORTER */}
          {importMode === 'jbb' && (
            <div className="card p-6 space-y-4">
              <div className="border-b border-navy-800 pb-3">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Ingest Behaviors CSV (JailbreakBench format)
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Converts standard JailbreakBench CSV datasets with columns (Index, Goal, Target, Behavior, Category, Source) into scanner YAML packs.
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
        </div>
      )}

      {/* TAB 2: EVALUATE JUDGE BENCHMARK */}
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
                  {evalLoading ? <Spinner size={14} /> : <Play size={14} />}
                  Run Judge Benchmark Evaluation
                </button>
              </div>
            </form>
          </div>

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
            </div>
          )}
        </div>
      )}
    </div>
  );
}
