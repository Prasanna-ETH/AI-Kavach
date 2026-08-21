import { useState, useEffect } from 'react';
import { 
  Search, 
  ChevronDown, 
  ChevronRight, 
  Code2 
} from 'lucide-react';
import { api } from '../api/client';
import type { PayloadPackInfo } from '../types';
import { SectionHeader, OwaspBadge, SeverityBadge, LoadingState, ErrorBanner } from '../components';

export default function PayloadLibrary() {
  const [packs, setPacks] = useState<PayloadPackInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [expandedPack, setExpandedPack] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        setError(null);
        const data = await api.getPayloadPacks();
        setPacks(data);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to load payload packs');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const toggleExpand = (name: string) => {
    setExpandedPack(prev => prev === name ? null : name);
  };

  const categories = Array.from(new Set(packs.map(p => p.category))).filter(Boolean);

  const filteredPacks = packs.filter(p => {
    if (selectedCategory !== 'ALL' && p.category !== selectedCategory) return false;
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      const matchName = p.name.toLowerCase().includes(q);
      const matchOwasp = p.owasp_id.toLowerCase().includes(q);
      const matchCat = p.category.toLowerCase().includes(q);
      if (!matchName && !matchOwasp && !matchCat) return false;
    }
    return true;
  });

  const totalVectors = packs.reduce((acc, p) => acc + p.count, 0);

  if (loading) {
    return <LoadingState message="Indexing YAML security payload packs..." />;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <SectionHeader
        title="OWASP Security Payload Library"
        subtitle={`Browse ${packs.length} attack payload packs containing ${totalVectors.toLocaleString()} security test vectors`}
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {/* Filter and Search Bar */}
      <div className="card p-4 flex flex-wrap gap-4 items-center justify-between">
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search by pack name, category, or OWASP ID (e.g. LLM01)..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="input-base text-xs pl-8"
            />
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-semibold">Category:</span>
          <select
            value={selectedCategory}
            onChange={e => setSelectedCategory(e.target.value)}
            className="input-base text-xs w-64"
          >
            <option value="ALL">All Categories ({packs.length} packs)</option>
            {categories.map(c => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Packs Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredPacks.map(pack => {
          const isExpanded = expandedPack === pack.name;
          return (
            <div
              key={pack.name}
              className={`card transition-all duration-200 ${
                isExpanded ? 'ring-1 ring-teal-500/60 bg-navy-800' : 'hover:border-navy-700'
              }`}
            >
              <div 
                className="p-5 cursor-pointer flex flex-col justify-between h-full"
                onClick={() => toggleExpand(pack.name)}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <OwaspBadge owaspId={pack.owasp_id} />
                    <span className="text-xs font-mono font-semibold text-slate-400 bg-navy-950 px-2 py-0.5 rounded border border-navy-800">
                      {pack.count} vectors
                    </span>
                  </div>

                  <h3 className="font-mono text-sm font-bold text-white mb-1 truncate" title={pack.name}>
                    {pack.name}
                  </h3>
                  <p className="text-xs text-slate-400 mb-3">{pack.category}</p>
                </div>

                <div className="pt-3 border-t border-navy-800 flex items-center justify-between text-xs text-slate-400">
                  <span className="font-mono text-[11px] text-slate-500 truncate max-w-[200px]">
                    {pack.file_path}
                  </span>
                  <div className="flex items-center gap-1 text-teal-400 font-medium">
                    {isExpanded ? (
                      <>Hide sample <ChevronDown size={14} /></>
                    ) : (
                      <>Inspect sample <ChevronRight size={14} /></>
                    )}
                  </div>
                </div>
              </div>

              {/* Sample Payload Drawer */}
              {isExpanded && pack.sample_payload && (
                <div className="p-5 bg-navy-950 border-t border-navy-800 text-xs space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-teal-400 flex items-center gap-1.5">
                      <Code2 size={13} /> Sample Attack Vector
                    </span>
                    <SeverityBadge severity={pack.sample_payload.severity} />
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase font-mono">Payload ID:</span>
                    <div className="font-mono text-xs text-slate-300">{pack.sample_payload.id}</div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase font-mono">Prompt Text:</span>
                    <div className="p-2.5 bg-navy-900 rounded font-mono text-xs text-slate-200 border border-navy-800 whitespace-pre-wrap max-h-48 overflow-y-auto">
                      {pack.sample_payload.prompt}
                    </div>
                  </div>

                  {pack.sample_payload.requires_llm_judge && (
                    <div className="text-[11px] text-amber-400 bg-amber-950/30 px-2 py-1 rounded border border-amber-800/40">
                      Requires LLM Judge evaluation for calibrated scoring
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
