import React, { useState } from 'react';
import { 
  BookOpen, 
  ShieldAlert, 
  Search, 
  FileCheck, 
  ExternalLink, 
  Sparkles, 
  Layers 
} from 'lucide-react';
import { MITRE_TECHNIQUES, CVE_RECORDS, SECURITY_POLICIES } from '../services/mockData';
import { soundFX } from '../services/soundEffects';

export const ThreatIntelView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'mitre' | 'cve' | 'policies' | 'vector_search'>('mitre');
  const [searchQuery, setSearchQuery] = useState<string>('');
  
  // Vector search playground state
  const [vectorQuery, setVectorQuery] = useState<string>('how to respond to high-volume DDoS SYN flood attack on edge web server?');
  const [isSearchingVector, setIsSearchingVector] = useState<boolean>(false);
  const [vectorResults, setVectorResults] = useState<any[]>([
    {
      id: 'mitre_T1498',
      type: 'MITRE ATT&CK',
      title: 'T1498: Network Denial of Service',
      similarity: 0.942,
      snippet: 'Adversaries may perform Network Denial of Service attacks to degrade or block the availability of targeted resources to users.',
    },
    {
      id: 'policy_POL_002',
      type: 'Security Policy',
      title: 'POL-002: DDoS & Volumetric Flood SLA',
      similarity: 0.895,
      snippet: 'Upon detection of sustained volumetric traffic exceeding 3x baseline, activate edge BGP Flowspec or Cloudflare Magic Transit scrubbing within 5 minutes.',
    },
  ]);

  const handleVectorSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vectorQuery.trim()) return;
    setIsSearchingVector(true);
    soundFX.playScan();

    await new Promise((r) => setTimeout(r, 600));

    const q = vectorQuery.toLowerCase();
    const results = [];
    if (q.includes('brute') || q.includes('ssh') || q.includes('password')) {
      results.push({
        id: 'mitre_T1110',
        type: 'MITRE ATT&CK',
        title: 'T1110: Brute Force',
        similarity: 0.938,
        snippet: 'Adversaries may use brute force techniques to attempt credential guessing across administrative interfaces.',
      });
      results.push({
        id: 'policy_POL_003',
        type: 'Security Policy',
        title: 'POL-003: Credential Stuffing Mitigation',
        similarity: 0.887,
        snippet: 'Enforce progressive IP rate-limiting, Fail2Ban rules, and MFA requirement after 5 failed authentication attempts.',
      });
    } else {
      results.push({
        id: 'mitre_T1498',
        type: 'MITRE ATT&CK',
        title: 'T1498: Network Denial of Service',
        similarity: 0.924,
        snippet: 'Volumetric or resource exhaustion targeting web servers and load balancers.',
      });
      results.push({
        id: 'policy_POL_002',
        type: 'Security Policy',
        title: 'POL-002: DDoS & Volumetric Flood SLA',
        similarity: 0.891,
        snippet: 'Perimeter firewall rate-limiting and SYN proxy enforcement.',
      });
    }

    setVectorResults(results);
    setIsSearchingVector(false);
    soundFX.playSuccess();
  };

  const filteredMitre = MITRE_TECHNIQUES.filter((t) =>
    t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    t.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    t.tactic.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredCve = CVE_RECORDS.filter((c) =>
    c.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c.summary.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredPolicies = SECURITY_POLICIES.filter((p) =>
    p.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    p.policy_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    p.mandate.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6 pb-12">
      {/* Header Banner */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-semibold text-indigo-600 mb-1">
            <BookOpen className="w-4 h-4" />
            <span>KNOWLEDGE BASE & RAG</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-900">
            Threat Intelligence & MITRE Matrix
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 mt-1">
            Explore adversary tactics, CVE records, security policies, and 384-dimensional dense vector embeddings.
          </p>
        </div>

        {/* Search */}
        <div className="relative w-full md:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search intelligence..."
            className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-900 focus:outline-none focus:border-indigo-500 focus:bg-white transition-colors"
          />
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-200 bg-white rounded-2xl p-1 shadow-xs space-x-1">
        {[
          { id: 'mitre', label: `MITRE ATT&CK (${filteredMitre.length})`, icon: ShieldAlert },
          { id: 'cve', label: `CVE Registry (${filteredCve.length})`, icon: Layers },
          { id: 'policies', label: `Security Policies (${filteredPolicies.length})`, icon: FileCheck },
          { id: 'vector_search', label: 'Semantic Vector Playground', icon: Sparkles },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id as any);
                soundFX.playClick();
              }}
              className={`flex-1 flex items-center justify-center space-x-2 py-2.5 px-3 rounded-xl text-xs font-semibold transition-all ${
                isActive
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-600 hover:bg-slate-50'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: MITRE ATT&CK */}
      {activeTab === 'mitre' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredMitre.map((tech) => (
            <div
              key={tech.id}
              className="p-5 rounded-2xl bg-white border border-slate-200 shadow-xs hover:border-indigo-300 transition-all space-y-3"
            >
              <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                <div className="flex items-center space-x-2">
                  <span className="px-2.5 py-0.5 rounded-md bg-amber-50 text-amber-800 font-mono font-bold text-xs">
                    {tech.id}
                  </span>
                  <span className="text-sm font-bold text-slate-900">{tech.name}</span>
                </div>
                <span className="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-medium">
                  {tech.tactic}
                </span>
              </div>

              <p className="text-xs text-slate-600 leading-relaxed">{tech.description}</p>

              <div className="space-y-1.5 pt-1 text-xs">
                <div className="font-semibold text-slate-800">Recommended Mitigation:</div>
                <p className="text-slate-600 text-[11px] bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                  {tech.mitigation}
                </p>
              </div>

              <div className="flex items-center justify-between pt-2 text-xs">
                <span className="text-slate-400 text-[11px]">Severity: <strong className="text-rose-600 uppercase font-semibold">{tech.severity_typical}</strong></span>
                <a
                  href={`https://attack.mitre.org/techniques/${tech.id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-indigo-600 hover:text-indigo-800 font-semibold flex items-center space-x-1"
                >
                  <span>MITRE Reference</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 2: CVE Records */}
      {activeTab === 'cve' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredCve.map((cve) => (
            <div
              key={cve.id}
              className="p-5 rounded-2xl bg-white border border-slate-200 shadow-xs hover:border-indigo-300 transition-all space-y-3"
            >
              <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                <div>
                  <span className="font-mono font-bold text-xs text-indigo-600">{cve.id}</span>
                  <h4 className="font-bold text-slate-900 text-xs mt-0.5">{cve.title}</h4>
                </div>
                <span className="px-2.5 py-0.5 rounded-full bg-rose-50 text-rose-700 font-bold text-xs">
                  CVSS {cve.cvss}
                </span>
              </div>

              <p className="text-xs text-slate-600 leading-relaxed">{cve.summary}</p>

              <div className="grid grid-cols-2 gap-2 text-xs pt-1">
                <div>
                  <span className="text-slate-400 block text-[11px]">Affected Software</span>
                  <span className="font-semibold text-slate-800">{cve.affected_software}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">Patch Status</span>
                  <span className="font-semibold text-emerald-600">{cve.patch_status}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 3: Security Policies */}
      {activeTab === 'policies' && (
        <div className="space-y-4">
          {filteredPolicies.map((pol) => (
            <div
              key={pol.policy_id}
              className="p-5 rounded-2xl bg-white border border-slate-200 shadow-xs space-y-3"
            >
              <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 font-mono font-bold text-xs">
                    {pol.policy_id}
                  </span>
                  <h3 className="text-sm font-bold text-slate-900">{pol.title}</h3>
                </div>
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 font-medium">
                  {pol.category}
                </span>
              </div>

              <p className="text-xs text-slate-600 leading-relaxed">{pol.mandate}</p>

              <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                <div className="text-xs font-semibold text-slate-800">Escalation & SLA</div>
                <p className="text-xs text-slate-600">{pol.escalation_path}</p>
                <div className="text-[11px] text-amber-700 font-medium pt-1">Target SLA: {pol.sla_minutes} minutes</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 4: Semantic Vector Search */}
      {activeTab === 'vector_search' && (
        <div className="space-y-6">
          <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-xs space-y-4">
            <div>
              <h3 className="text-base font-bold text-slate-900 flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-indigo-600" />
                <span>Qdrant Dense Vector Semantic Search Playground</span>
              </h3>
              <p className="text-xs text-slate-500 mt-1">
                Enter any natural language cyber threat inquiry to perform real-time cosine distance matching against the embedded MITRE ATT&CK knowledge base.
              </p>
            </div>

            <form onSubmit={handleVectorSearch} className="flex space-x-2">
              <input
                type="text"
                value={vectorQuery}
                onChange={(e) => setVectorQuery(e.target.value)}
                placeholder="Ask any incident question, e.g. How to mitigate brute force logins..."
                className="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-4 py-2.5 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:bg-white"
              />
              <button
                type="submit"
                disabled={isSearchingVector}
                className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs transition-all flex items-center space-x-1.5 shadow-xs disabled:opacity-50"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{isSearchingVector ? 'Embedding...' : 'Vector Search'}</span>
              </button>
            </form>
          </div>

          {/* Results */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
              Vector Match Results ({vectorResults.length})
            </h4>
            {vectorResults.map((res, i) => (
              <div
                key={i}
                className="p-5 rounded-2xl bg-white border border-slate-200 shadow-xs hover:border-indigo-300 transition-all space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 text-xs font-bold font-mono">
                      {res.id}
                    </span>
                    <span className="font-bold text-sm text-slate-900">{res.title}</span>
                  </div>
                  <span className="px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 font-mono font-bold text-xs">
                    {(res.similarity * 100).toFixed(1)}% Cosine Match
                  </span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">{res.snippet}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
