import React, { useState, useEffect } from 'react';

const ImmuniSOCDashboard = () => {
  const [metrics, setMetrics] = useState({
    internalChecks: 52041,
    activeQuarantines: 2,
    canaryTriggers: 0
  });
  const [quarantines, setQuarantines] = useState<Array<{session_id:string,reason:string,timestamp:string}>>([]);

  useEffect(() => {
    let mounted = true;
    const fetchQuarantines = async () => {
      try {
        const res = await fetch('http://localhost:8090/quarantines');
        if (!res.ok) return;
        const data = await res.json();
        if (mounted) setQuarantines(data);
      } catch (e) {
        // ignore network errors during dev
      }
    };
    fetchQuarantines();
    const id = setInterval(fetchQuarantines, 5000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8 font-sans">
      <header className="mb-8 border-b border-gray-700 pb-4 flex justify-between">
        <div>
          <h1 className="text-3xl font-bold text-blue-400">ImmuniSOC-Nexus</h1>
          <p className="text-gray-400">Bio-Inspired Security Governance Hub</p>
        </div>
        <div className="text-right">
          <span className="bg-green-900 text-green-300 px-3 py-1 rounded-full text-sm">
            Hermes AI: Monitoring
          </span>
        </div>
      </header>

      <div className="grid grid-cols-3 gap-6 mb-8">
        <div className="bg-gray-800 p-6 rounded-lg border-l-4 border-blue-500">
          <h3 className="text-gray-400 text-sm">Neutrophil Checks / Sec</h3>
          <p className="text-4xl font-bold">{metrics.internalChecks}</p>
        </div>
        <div className="bg-gray-800 p-6 rounded-lg border-l-4 border-red-500">
          <h3 className="text-gray-400 text-sm">T-Cell Quarantines (Active)</h3>
          <p className="text-4xl font-bold text-red-400">{metrics.activeQuarantines}</p>
        </div>
        <div className="bg-gray-800 p-6 rounded-lg border-l-4 border-yellow-500">
          <h3 className="text-gray-400 text-sm">Deception Mesh Triggers</h3>
          <p className="text-4xl font-bold text-yellow-400">{metrics.canaryTriggers}</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-800 p-6 rounded-lg">
          <h2 className="text-xl font-semibold mb-4 border-b border-gray-700 pb-2">
            Active Security Tiers
          </h2>
          <ul className="space-y-4">
            <li className="flex justify-between">
              <span className="text-blue-400 font-bold">CRITICAL</span>
              <span className="text-sm text-gray-400">HSM Decrypt | gVisor Cold-Start</span>
            </li>
            <li className="flex justify-between">
              <span className="text-purple-400 font-bold">STANDARD</span>
              <span className="text-sm text-gray-400">Pre-warmed gVisor | B-Cell Adaptive</span>
            </li>
            <li className="flex justify-between">
              <span className="text-green-400 font-bold">PUBLIC</span>
              <span className="text-sm text-gray-400">Read-Only Replica | No Write Path</span>
            </li>
          </ul>
        </div>

        <div className="bg-gray-800 p-6 rounded-lg">
          <h2 className="text-xl font-semibold mb-4 border-b border-gray-700 pb-2">
            Monocyte Audit Log (Recent)
          </h2>
          <div className="space-y-2 text-sm font-mono">
            <p className="text-gray-400">[13:41:02] SPIFFE cert issued to service-billing</p>
            <p className="text-gray-400">[13:41:05] OPA live evaluation passed for User A</p>
            <p className="text-red-400">[13:41:10] ALERT: Volumetric spike detected by Hermes AI</p>
            <p className="text-green-400">[13:41:10] ACTION: T-Cell revoked JIT token (140ms latency)</p>
          </div>
        </div>
        <div className="bg-gray-800 p-6 rounded-lg">
          <h2 className="text-xl font-semibold mb-4 border-b border-gray-700 pb-2">
            T-Cell Quarantine Log (Recent)
          </h2>
          <div className="space-y-2 text-sm font-mono max-h-48 overflow-auto">
            {quarantines.length === 0 && (
              <p className="text-gray-400">No quarantined sessions</p>
            )}
            {quarantines.map((q) => (
              <div key={q.session_id} className="border-b border-gray-700 pb-2">
                <p className="text-red-400">{q.reason}</p>
                <p className="text-gray-400 text-xs">{q.session_id} — {new Date(q.timestamp).toLocaleString()}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ImmuniSOCDashboard;
