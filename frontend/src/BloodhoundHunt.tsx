import { useEffect, useState } from 'react';
import { Target, Search, Activity, Shield } from 'lucide-react';

const BloodhoundHunt = () => {
  const [step, setStep] = useState(0);

  const chaseSteps = [
    { label: 'Analyzing Ingress Point', status: 'COMPLETE', node: 'Edge_Router_01' },
    { label: 'Tracing Lateral Movement', status: 'ACTIVE', node: 'Internal_App_Srv' },
    { label: 'Isolating Compromised Node', status: 'PENDING', node: 'User_Auth_Vault' },
    { label: 'Neutralizing Vector', status: 'PENDING', node: 'N/A' },
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setStep((s) => (s + 1) % 4);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass-panel p-6 overflow-hidden relative">
      <div className="scanline"></div>
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-white font-semibold flex items-center gap-2">
          <Target className="w-4 h-4 text-primary animate-pulse" />
          Active Bloodhound Hunt
        </h3>
        <span className="text-[10px] text-primary/60 font-mono tracking-widest animate-pulse">HUNTING_SESSION: 0x8F2C</span>
      </div>

      <div className="relative">
        {/* The Graph Visual */}
        <div className="h-40 flex items-center justify-around mb-8 relative">
          <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-20">
            <line x1="25%" y1="50%" x2="50%" y2="50%" stroke="currentColor" strokeWidth="1" className="text-primary" />
            <line x1="50%" y1="50%" x2="75%" y2="50%" stroke="currentColor" strokeWidth="1" className="text-primary" />
          </svg>

          <Node icon={Globe} label="WAN" active={step >= 0} current={step === 0} />
          <Node icon={Activity} label="Router" active={step >= 1} current={step === 1} />
          <Node icon={Shield} label="Vault" active={step >= 2} current={step === 2} />
          <Node icon={Search} label="Target" active={step >= 3} current={step === 3} danger />
        </div>

        {/* Step List */}
        <div className="space-y-3">
          {chaseSteps.map((s, i) => (
            <div key={i} className={`flex items-center justify-between p-2 rounded border transition-all duration-500 ${i === step ? 'bg-primary/10 border-primary/30' : 'bg-transparent border-transparent'}`}>
              <div className="flex items-center gap-3">
                <div className={`w-1.5 h-1.5 rounded-full ${i < step ? 'bg-success' : i === step ? 'bg-primary animate-pulse' : 'bg-slate-700'}`} />
                <span className={`text-[11px] font-mono ${i === step ? 'text-white' : 'text-slate-500'}`}>{s.label}</span>
              </div>
              {i === step && (
                <div className="text-[9px] font-mono text-primary animate-pulse tracking-tighter">
                  LOCATING: {s.node}
                </div>
              )}
              {i < step && (
                <div className="text-[9px] font-mono text-success tracking-tighter">
                  CLEARED
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="operative-note mt-6">
        "Operative 04: Bloodhound is picking up a scent near the auth vault. Lateral movement is highly sophisticated. Adjusting T-Cell response to High-Criticality."
      </div>
    </div>
  );
};

const Node = ({ icon: Icon, label, active, current, danger }: any) => (
  <div className="flex flex-col items-center gap-2 relative z-10">
    <div className={`w-10 h-10 rounded-xl flex items-center justify-center border-2 transition-all duration-1000 ${
      current ? (danger ? 'bg-danger/20 border-danger scale-125 animate-bounce' : 'bg-primary/20 border-primary scale-125') :
      active ? 'bg-primary/5 border-primary/40 opacity-100' : 'bg-surface border-white/5 opacity-40'
    }`}>
      <Icon className={`w-5 h-5 ${current && danger ? 'text-danger' : current ? 'text-primary' : 'text-slate-500'}`} />
    </div>
    <span className={`text-[9px] font-mono ${current ? 'text-white' : 'text-slate-600'}`}>{label}</span>
  </div>
);

const Globe = ({ className }: any) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
  </svg>
);

export default BloodhoundHunt;
