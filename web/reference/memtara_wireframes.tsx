import React, { useState, useEffect } from 'react';
import {
  Shield, Clock, Check, ChevronRight, FileText,
  Smartphone, Monitor, Lock, EyeOff, Search,
  Activity, ArrowRight, Building, CheckCircle2,
  RefreshCw, SlidersHorizontal, Globe, MapPin
} from 'lucide-react';

// Injecting the required fonts (PT Serif and IBM Plex Mono)
const FontStyles = () => (
  <style dangerouslySetInnerHTML={{__html: `
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,400;0,500;1,400&family=PT+Serif:ital,wght@0,400;0,700;1,400&display=swap');

    :root {
      --paper-bg: #F7F5F0;
      --paper-dark: #EAE6DB;
      --ink-main: #1A1A1A;
      --ink-light: #5A5A55;
      --border-color: #DCD7CB;
      --accent-muted: #8E8A80;
    }

    body {
      background-color: var(--paper-bg);
      color: var(--ink-main);
      font-family: 'PT Serif', serif;
    }

    .font-mono {
      font-family: 'IBM Plex Mono', monospace;
    }

    .redacted {
      background-color: var(--ink-main);
      color: var(--ink-main);
      user-select: none;
      border-radius: 2px;
      display: inline-block;
      transition: all 0.3s ease;
    }

    .redacted:hover {
      background-color: transparent;
      color: var(--ink-light);
      box-shadow: 0 1px 0 var(--ink-light);
    }

    .hide-scrollbar::-webkit-scrollbar {
      display: none;
    }
    .hide-scrollbar {
      -ms-overflow-style: none;
      scrollbar-width: none;
    }

    .glass-panel {
      background: rgba(247, 245, 240, 0.8);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
    }
  `}} />
);

const RedactedText = ({ text, isRedacted }) => {
  return isRedacted ? (
    <span className="redacted px-1">{text}</span>
  ) : (
    <span className="text-ink-main">{text}</span>
  );
};

const ZKProofSimulator = ({ onComplete }) => {
  const [log, setLog] = useState([]);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const steps = [
      "Initializing local circuit environment...",
      "Loading specific predicate constraints...",
      "Hashing local vault state...",
      "Computing zero-knowledge proof...",
      "Verifying proof integrity locally...",
      "Generating ephemeral session token..."
    ];

    let currentStep = 0;
    const interval = setInterval(() => {
      if (currentStep < steps.length) {
        setLog(prev => [...prev, steps[currentStep]]);
        setProgress(((currentStep + 1) / steps.length) * 100);
        currentStep++;
      } else {
        clearInterval(interval);
        setTimeout(onComplete, 500);
      }
    }, 400);

    return () => clearInterval(interval);
  }, [onComplete]);

  return (
    <div className="bg-[#1A1A1A] p-6 rounded-lg text-[#EAE6DB] font-mono text-xs shadow-2xl overflow-hidden relative">
      <div className="absolute top-0 left-0 w-full h-1 bg-[#333]">
        <div
          className="h-full bg-white transition-all duration-300 ease-out"
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="flex items-center gap-2 mb-4 text-[#8E8A80]">
        <Lock size={14} />
        <span>ON-DEVICE COMPUTATION</span>
      </div>
      <div className="space-y-2 h-32 overflow-y-auto hide-scrollbar">
        {log.map((line, i) => (
          <div key={i} className="flex gap-2 opacity-80 animate-pulse">
            <span className="text-[#8E8A80]">{'>'}</span> {line}
          </div>
        ))}
      </div>
    </div>
  );
};

const EnterpriseBankView = () => {
  const [sessionActive, setSessionActive] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [selectedPolicies, setSelectedPolicies] = useState({
    riskFlags: true,
    pepStatus: true,
    sourceOfFunds: false,
    history90Days: false
  });

  const handleStartSession = () => {
    setGenerating(true);
  };

  const completeGeneration = () => {
    setGenerating(false);
    setSessionActive(true);
  };

  return (
    <div className="w-full h-full min-h-screen p-8" style={{ backgroundColor: 'var(--paper-bg)' }}>
      <header className="flex justify-between items-center mb-10 pb-6 border-b" style={{ borderColor: 'var(--border-color)' }}>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Memtara</h1>
          <p className="font-mono text-sm mt-1" style={{ color: 'var(--ink-light)' }}>Compliance Analyst Portal â¢ Terminal 04</p>
        </div>
        <div className="flex items-center gap-4 font-mono text-sm">
          <span className="px-3 py-1 border rounded-full border-black flex items-center gap-2">
            <Activity size={14} /> Encrypted Enclave
          </span>
        </div>
      </header>

      <div className="grid grid-cols-12 gap-8 h-[75vh]">

        {/* Left Column: Redacted Vault Preview */}
        <div className="col-span-5 flex flex-col border p-6 rounded-lg bg-white shadow-sm" style={{ borderColor: 'var(--border-color)' }}>
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-lg font-bold flex items-center gap-2">
              <EyeOff size={18} /> Vault Preview
            </h2>
            <span className="font-mono text-xs uppercase tracking-widest text-red-600 font-bold border border-red-600 px-2 py-1 rounded">Confidential</span>
          </div>

          <div className="flex-1 overflow-y-auto pr-4 hide-scrollbar space-y-6 text-sm leading-relaxed">
            <div>
              <p className="font-mono text-xs uppercase mb-2" style={{ color: 'var(--ink-light)' }}>Client Identity</p>
              <p>Name: <RedactedText text="Ahmed Al Mansoori" isRedacted={true} /></p>
              <p>EID: <RedactedText text="784-1985-1234567-1" isRedacted={true} /></p>
              <p>DOB: <RedactedText text="14/08/1985" isRedacted={true} /></p>
            </div>

            <div className="pt-4 border-t" style={{ borderColor: 'var(--border-color)' }}>
              <p className="font-mono text-xs uppercase mb-2" style={{ color: 'var(--ink-light)' }}>Risk & Compliance Flags</p>
              <p>PEP Status: <RedactedText text="Negative (Cleared)" isRedacted={!selectedPolicies.pepStatus} /></p>
              <p>Sanctions Match: <RedactedText text="None" isRedacted={!selectedPolicies.riskFlags} /></p>
              <p>Risk Score: <RedactedText text="Low (12/100)" isRedacted={!selectedPolicies.riskFlags} /></p>
            </div>

            <div className="pt-4 border-t" style={{ borderColor: 'var(--border-color)' }}>
              <p className="font-mono text-xs uppercase mb-2" style={{ color: 'var(--ink-light)' }}>Financial Profile</p>
              <p>Source of Funds: <RedactedText text="Salary - Government Sector" isRedacted={!selectedPolicies.sourceOfFunds} /></p>
              <p>Est. Net Worth: <RedactedText text="> AED 5,000,000" isRedacted={true} /></p>
              <p>Account Balance: <RedactedText text="AED 450,210.50" isRedacted={true} /></p>
            </div>

            <div className="pt-4 border-t" style={{ borderColor: 'var(--border-color)' }}>
              <p className="font-mono text-xs uppercase mb-2 flex items-center gap-2" style={{ color: 'var(--ink-light)' }}>
                Transaction Anomalies (90 Days)
              </p>
              {selectedPolicies.history90Days ? (
                <div className="space-y-2">
                  <div className="p-2 bg-gray-50 border rounded font-mono text-xs">No large structured deposits detected. Normal payroll activity.</div>
                </div>
              ) : (
                <div className="p-4 bg-gray-100 flex items-center justify-center font-mono text-xs text-gray-500 rounded border border-dashed">
                  <Lock size={12} className="mr-2" /> Section Redacted by Policy
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Policy Builder & AI Session */}
        <div className="col-span-7 flex flex-col">
          {!sessionActive && !generating ? (
            <div className="border p-8 rounded-lg flex-1 flex flex-col" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--paper-dark)' }}>
              <div className="mb-8">
                <h2 className="text-2xl font-bold mb-2">AI Session â Compliance Assist</h2>
                <p style={{ color: 'var(--ink-light)' }}>Define the minimal disclosure policy required to generate the STR narrative. Raw data will not leave this device.</p>
              </div>

              <div className="space-y-4 mb-8 flex-1">
                <p className="font-mono text-xs uppercase font-bold tracking-wider">Select Verified Attributes for AI Context</p>

                {Object.entries(selectedPolicies).map(([key, value]) => (
                  <label key={key} className="flex items-center justify-between p-4 bg-white border rounded cursor-pointer hover:bg-gray-50 transition-colors shadow-sm" style={{ borderColor: 'var(--border-color)' }}>
                    <div className="flex items-center gap-3">
                      <div className={`w-5 h-5 border flex items-center justify-center rounded-sm ${value ? 'bg-black border-black' : 'border-gray-400'}`}>
                        {value && <Check size={14} color="white" />}
                      </div>
                      <span className="font-medium capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</span>
                    </div>
                    <span className="font-mono text-xs text-gray-500">{value ? 'Included in Proof' : 'Redacted'}</span>
                  </label>
                ))}
              </div>

              <div className="flex items-center gap-6 p-4 border-t" style={{ borderColor: 'var(--border-color)' }}>
                <div className="flex-1">
                  <p className="font-mono text-xs uppercase mb-1">Session Duration</p>
                  <p className="font-medium flex items-center gap-2"><Clock size={16}/> 15 Minutes</p>
                </div>
                <button
                  onClick={handleStartSession}
                  className="bg-black text-white px-8 py-3 rounded hover:bg-gray-800 transition-colors font-medium flex items-center gap-2"
                >
                  Generate Local Proof & Start Session <ChevronRight size={18} />
                </button>
              </div>
            </div>
          ) : generating ? (
            <div className="flex-1 flex flex-col justify-center items-center">
              <div className="w-full max-w-md">
                <ZKProofSimulator onComplete={completeGeneration} />
              </div>
            </div>
          ) : (
            <div className="border rounded-lg flex-1 flex flex-col bg-white overflow-hidden shadow-sm" style={{ borderColor: 'var(--border-color)' }}>
              <div className="bg-black text-white p-4 flex justify-between items-center">
                <div className="flex items-center gap-2 font-mono text-sm">
                  <Shield size={16} className="text-green-400" />
                  ZK-Verified AI Assistant
                </div>
                <div className="font-mono text-xs text-gray-400 flex items-center gap-2">
                  <Clock size={12} /> Auto-expires in 14:59
                </div>
              </div>

              <div className="flex-1 p-6 overflow-y-auto space-y-6">
                <div className="flex gap-4">
                  <div className="w-8 h-8 bg-gray-100 rounded-full flex items-center justify-center flex-shrink-0 font-bold border border-gray-300">
                    AI
                  </div>
                  <div className="bg-gray-50 p-4 rounded-lg rounded-tl-none border font-mono text-sm" style={{ borderColor: 'var(--border-color)' }}>
                    <p className="mb-2">I have received the zero-knowledge proof verifying the following attributes for the client:</p>
                    <ul className="list-disc pl-4 space-y-1 mb-4 text-gray-600">
                      <li>Risk Flags: None</li>
                      <li>PEP Status: Negative</li>
                    </ul>
                    <p>Based on this minimal dataset, I am drafting the clearance memo. Do you need me to cross-reference the source of funds?</p>
                  </div>
                </div>

                <div className="flex gap-4 flex-row-reverse">
                  <div className="w-8 h-8 bg-black text-white rounded-full flex items-center justify-center flex-shrink-0 font-bold font-mono text-xs">
                    YOU
                  </div>
                  <div className="bg-blue-50 p-4 rounded-lg rounded-tr-none border border-blue-100 font-mono text-sm">
                    No, the current proof is sufficient. Please generate the final standard STR clearance narrative based solely on the verified absence of PEP and Risk flags.
                  </div>
                </div>
              </div>

              <div className="p-4 border-t bg-gray-50 flex gap-2" style={{ borderColor: 'var(--border-color)' }}>
                <input type="text" placeholder="Type a command..." className="flex-1 border p-2 rounded font-mono text-sm bg-white" style={{ borderColor: 'var(--border-color)' }} />
                <button className="bg-black text-white px-4 rounded font-mono text-sm">Send</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const MobileAppView = () => {
  const [step, setStep] = useState('dashboard'); // dashboard, request, proof, success

  const navigateTo = (newStep) => setStep(newStep);

  return (
    <div className="w-full h-full min-h-screen flex items-center justify-center py-12" style={{ backgroundColor: 'var(--paper-dark)' }}>
      {/* Phone Mockup Frame */}
      <div className="relative w-[390px] h-[844px] bg-white rounded-[50px] shadow-2xl border-[8px] border-gray-900 overflow-hidden flex flex-col font-sans">

        {/* Status Bar Mock */}
        <div className="h-12 w-full flex justify-between items-center px-6 pt-2 text-black bg-white z-50">
          <span className="font-medium text-sm">9:41</span>
          <div className="flex items-center gap-1.5">
            <div className="w-4 h-3 bg-black rounded-sm"></div>
            <div className="w-3 h-3 bg-black rounded-full"></div>
            <div className="w-5 h-3 bg-black rounded-sm"></div>
          </div>
        </div>

        {/* App Content Area */}
        <div className="flex-1 overflow-y-auto bg-[#F7F5F0] hide-scrollbar relative">

          {step === 'dashboard' && (
            <div className="p-6 pb-24">
              <div className="flex justify-between items-center mb-8">
                <h1 className="font-serif text-3xl font-bold">Memtara</h1>
                <div className="w-10 h-10 bg-black rounded-full flex items-center justify-center text-white">
                  <Search size={18} />
                </div>
              </div>

              {/* Active Request Alert */}
              <div
                onClick={() => navigateTo('request')}
                className="bg-white border p-5 rounded-2xl mb-8 shadow-sm cursor-pointer hover:shadow-md transition-shadow relative overflow-hidden group"
                style={{ borderColor: 'var(--border-color)' }}
              >
                <div className="absolute top-0 left-0 w-1 h-full bg-blue-600"></div>
                <div className="flex justify-between items-start mb-2">
                  <span className="font-mono text-[10px] uppercase font-bold tracking-widest text-blue-600">Pending Request</span>
                  <span className="font-mono text-[10px] text-gray-400 flex items-center gap-1"><Clock size={10}/> 2m ago</span>
                </div>
                <h3 className="font-serif font-bold text-lg mb-1">Mortgage Pre-Approval</h3>
                <p className="text-sm text-gray-600 mb-4">Emaar Properties is requesting verified attributes.</p>
                <div className="flex items-center text-sm font-medium text-black">
                  Review Policy <ArrowRight size={16} className="ml-2 group-hover:translate-x-1 transition-transform" />
                </div>
              </div>

              {/* Vault Badges (Journey 4 context) */}
              <h2 className="font-serif font-bold text-lg mb-4">Your Verified Credentials</h2>
              <div className="space-y-4">

                {/* Golden Visa Card */}
                <div className="bg-[#1A1A1A] text-[#F7F5F0] p-5 rounded-2xl shadow-lg relative overflow-hidden">
                  <div className="absolute -right-4 -top-4 opacity-10">
                    <Globe size={100} />
                  </div>
                  <div className="flex items-center gap-3 mb-6">
                    <Shield size={20} className="text-yellow-500" />
                    <span className="font-mono text-xs uppercase tracking-widest text-yellow-500">Active Credential</span>
                  </div>
                  <h3 className="font-serif font-bold text-xl mb-1">UAE Golden Visa</h3>
                  <p className="font-mono text-xs opacity-70 mb-4">Investor Category â¢ Expires 2036</p>
                  <div className="flex justify-between items-center pt-4 border-t border-gray-700">
                    <span className="text-xs">Stored Locally</span>
                    <button className="text-xs font-medium border border-gray-600 px-3 py-1.5 rounded-full hover:bg-gray-800">
                      Share Proof
                    </button>
                  </div>
                </div>

                {/* Salary Range Card */}
                <div className="bg-white border p-5 rounded-2xl shadow-sm" style={{ borderColor: 'var(--border-color)' }}>
                  <div className="flex items-center gap-3 mb-4">
                    <Building size={18} className="text-gray-400" />
                    <span className="font-mono text-xs uppercase tracking-widest text-gray-500">Employment</span>
                  </div>
                  <h3 className="font-serif font-bold text-lg mb-1">Salary Tier Verified</h3>
                  <p className="font-mono text-xs text-gray-500">Level 4 (&gt; AED 40k) â¢ Updated 12 Oct</p>
                </div>
              </div>
            </div>
          )}

          {step === 'request' && (
            <div className="flex flex-col h-full bg-white">
              <div className="p-6 pb-4 border-b border-gray-100 flex items-center gap-4">
                <button onClick={() => navigateTo('dashboard')} className="p-2 -ml-2 rounded-full hover:bg-gray-100">
                  <ChevronRight size={24} className="rotate-180" />
                </button>
                <h2 className="font-serif font-bold text-xl">Review Disclosure</h2>
              </div>

              <div className="p-6 flex-1 overflow-y-auto hide-scrollbar">
                <div className="flex items-center gap-4 mb-6">
                  <div className="w-12 h-12 bg-gray-100 rounded-xl flex items-center justify-center">
                    <MapPin size={24} className="text-gray-700" />
                  </div>
                  <div>
                    <h3 className="font-bold text-lg">Emaar Properties</h3>
                    <p className="text-sm text-gray-500">Requires proof for Mortgage Pre-approval</p>
                  </div>
                </div>

                {/* The Core Concept: What they see vs What stays private */}
                <div className="bg-[#F7F5F0] rounded-2xl p-1 mt-6">
                  <div className="bg-white rounded-xl p-5 shadow-sm border border-gray-100">
                    <div className="flex justify-between items-center border-b border-gray-100 pb-4 mb-4">
                      <span className="font-mono text-xs font-bold uppercase tracking-wider text-black">What They Receive</span>
                      <span className="font-mono text-[10px] bg-green-100 text-green-700 px-2 py-1 rounded">ZK PROOF</span>
                    </div>
                    <ul className="space-y-4">
                      <li className="flex items-start gap-3">
                        <CheckCircle2 size={18} className="text-green-600 mt-0.5" />
                        <div>
                          <p className="font-medium text-sm">Residency Verified</p>
                          <p className="text-xs text-gray-500">Boolean (True)</p>
                        </div>
                      </li>
                      <li className="flex items-start gap-3">
                        <CheckCircle2 size={18} className="text-green-600 mt-0.5" />
                        <div>
                          <p className="font-medium text-sm">Income Tier â¥ AED 40k</p>
                          <p className="text-xs text-gray-500">Boolean (True)</p>
                        </div>
                      </li>
                    </ul>
                  </div>

                  <div className="p-5">
                    <div className="flex justify-between items-center mb-4">
                      <span className="font-mono text-xs font-bold uppercase tracking-wider text-gray-500">What Stays Private</span>
                      <span className="font-mono text-[10px] bg-gray-200 text-gray-600 px-2 py-1 rounded flex items-center gap-1"><Lock size={10}/> ON DEVICE</span>
                    </div>
                    <ul className="space-y-3 font-mono text-xs text-gray-500">
                      <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 rounded-full bg-gray-400"></div> Exact Salary Amount</li>
                      <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 rounded-full bg-gray-400"></div> Employer Name</li>
                      <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 rounded-full bg-gray-400"></div> Passport Copy</li>
                      <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 rounded-full bg-gray-400"></div> Bank Statements</li>
                    </ul>
                  </div>
                </div>

                <div className="mt-8 border-t border-gray-100 pt-6">
                  <p className="font-mono text-xs font-bold uppercase tracking-wider text-black mb-4">Expiry Timer</p>
                  <div className="flex gap-2">
                    <button className="flex-1 py-2 rounded-lg border-2 border-black font-medium text-sm">15 Mins</button>
                    <button className="flex-1 py-2 rounded-lg border border-gray-200 text-gray-500 font-medium text-sm">24 Hrs</button>
                    <button className="flex-1 py-2 rounded-lg border border-gray-200 text-gray-500 font-medium text-sm">7 Days</button>
                  </div>
                </div>
              </div>

              <div className="p-6 pt-2 bg-white">
                <button
                  onClick={() => navigateTo('proof')}
                  className="w-full bg-black text-white py-4 rounded-xl font-bold text-lg flex items-center justify-center gap-2 shadow-lg shadow-black/20 hover:scale-[1.02] transition-transform"
                >
                  <RefreshCw size={18} /> Generate Local Proof
                </button>
              </div>
            </div>
          )}

          {step === 'proof' && (
            <div className="h-full flex flex-col items-center justify-center p-8 bg-[#1A1A1A] text-white">
              <div className="w-full">
                <ZKProofSimulator onComplete={() => navigateTo('success')} />
              </div>
              <p className="mt-8 text-center text-sm text-gray-400 font-mono">
                Your full documents never leave this phone. Only the mathematical proof is transmitted.
              </p>
            </div>
          )}

          {step === 'success' && (
            <div className="h-full flex flex-col items-center justify-center p-8 bg-[#F7F5F0]">
              <div className="w-24 h-24 bg-green-100 text-green-600 rounded-full flex items-center justify-center mb-8 shadow-inner">
                <Check size={48} strokeWidth={3} />
              </div>
              <h2 className="font-serif font-bold text-2xl text-center mb-2">Proof Shared Securely</h2>
              <p className="text-center text-gray-600 mb-8 font-serif">
                Emaar Properties has verified your attributes.
              </p>

              <div className="w-full bg-white border p-4 rounded-xl mb-12 shadow-sm font-mono text-xs" style={{ borderColor: 'var(--border-color)' }}>
                <div className="flex justify-between items-center mb-2 border-b border-dashed pb-2">
                  <span className="text-gray-500">Session ID</span>
                  <span className="font-bold">#MEM-8842-A1</span>
                </div>
                <div className="flex justify-between items-center mb-2 border-b border-dashed pb-2">
                  <span className="text-gray-500">Recipient</span>
                  <span className="font-bold">Emaar Portal</span>
                </div>
                <div className="flex justify-between items-center text-red-600">
                  <span>Auto-Revokes In</span>
                  <span className="font-bold">14:59</span>
                </div>
              </div>

              <button
                onClick={() => navigateTo('dashboard')}
                className="w-full bg-transparent border-2 border-black text-black py-4 rounded-xl font-bold text-lg hover:bg-black hover:text-white transition-colors"
              >
                Return to Vault
              </button>
            </div>
          )}

        </div>

        {/* Home Indicator Mock */}
        <div className="h-8 w-full bg-white flex items-center justify-center pb-2 z-50">
          <div className="w-1/3 h-1 bg-black rounded-full"></div>
        </div>
      </div>
    </div>
  );
};

export default function MemtaraPrototype() {
  const [activeView, setActiveView] = useState('enterprise'); // 'enterprise' or 'mobile'

  return (
    <div className="min-h-screen flex flex-col font-sans selection:bg-black selection:text-white">
      <FontStyles />

      {/* Top Prototype Navigation */}
      <div className="bg-black text-white p-4 flex justify-between items-center sticky top-0 z-50 shadow-md">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 border-2 border-white rounded-sm flex items-center justify-center">
            <div className="w-2 h-2 bg-white rounded-sm"></div>
          </div>
          <span className="font-mono text-sm tracking-widest uppercase font-bold">Memtara Design Prototype</span>
        </div>

        <div className="flex bg-[#222] p-1 rounded-lg border border-[#333]">
          <button
            onClick={() => setActiveView('enterprise')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md font-mono text-xs transition-colors ${activeView === 'enterprise' ? 'bg-white text-black' : 'text-gray-400 hover:text-white'}`}
          >
            <Monitor size={14} /> Bank Analyst View
          </button>
          <button
            onClick={() => setActiveView('mobile')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md font-mono text-xs transition-colors ${activeView === 'mobile' ? 'bg-white text-black' : 'text-gray-400 hover:text-white'}`}
          >
            <Smartphone size={14} /> Consumer App
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 overflow-hidden relative flex">
        {activeView === 'enterprise' ? <EnterpriseBankView /> : <MobileAppView />}
      </main>

      {/* Design System Reference Footer */}
      <footer className="bg-white border-t border-gray-200 p-3 text-center flex justify-center gap-8 font-mono text-[10px] text-gray-500">
        <span>Typography: PT Serif + IBM Plex Mono</span>
        <span>Aesthetic: Prove, don't expose</span>
        <span>Theme: Warm Paper & Quiet Confidence</span>
        <span dir="rtl" className="font-sans ml-4 border-l pl-4">Ø¬Ø§ÙØ² ÙÙØºØ© Ø§ÙØ¹Ø±Ø¨ÙØ©</span>
      </footer>
    </div>
  );
}
