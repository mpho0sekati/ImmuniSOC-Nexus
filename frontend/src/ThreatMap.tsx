import { useMemo } from 'react';

const ThreatMap = ({ threats }: { threats: any[] }) => {
  // Mock coordinates for major cities/regions
  const locations = useMemo(() => ({
    'USA': { x: 180, y: 150 },
    'China': { x: 650, y: 180 },
    'Russia': { x: 600, y: 100 },
    'Brazil': { x: 300, y: 320 },
    'UK': { x: 420, y: 110 },
    'Germany': { x: 450, y: 120 },
    'South Africa': { x: 480, y: 350 },
    'Australia': { x: 700, y: 350 },
    'India': { x: 580, y: 220 },
  }), []);

  const activeThreats = useMemo(() => {
    return threats.slice(0, 4).map((t, i) => {
      const keys = Object.keys(locations);
      const loc = locations[keys[i % keys.length] as keyof typeof locations];
      return { ...t, ...loc };
    });
  }, [threats, locations]);

  return (
    <div className="relative w-full aspect-[2/1] bg-surface/30 rounded-xl overflow-hidden border border-white/5">
      <div className="scanline"></div>
      <svg viewBox="0 0 800 400" className="w-full h-full opacity-40 grayscale">
        {/* Simplified World Map SVG Path - Artisanal Representation */}
        <path
          d="
            M120,80 L180,80 L200,120 L180,180 L140,180 L100,140 Z
            M140,190 L180,190 L190,250 L170,320 L140,280 L130,220 Z
            M380,60 L550,60 L650,100 L700,180 L650,250 L550,280 L450,280 L380,220 Z
            M420,180 L480,180 L500,220 L480,280 L440,300 L400,250 Z
            M650,280 L720,280 L750,320 L720,360 L650,340 Z
          "
          fill="none"
          stroke="currentColor"
          strokeWidth="1"
          className="text-slate-700"
        />
        {/* Add more decorative grid */}
        <path d="M0,100 L800,100 M0,200 L800,200 M0,300 L800,300 M200,0 L200,400 M400,0 L400,400 M600,0 L600,400" stroke="currentColor" strokeWidth="0.5" className="text-white/5" />
      </svg>

      {/* Legend */}
      <div className="absolute top-4 left-4 font-mono text-[10px] text-slate-500 uppercase tracking-widest bg-black/40 px-2 py-1 rounded border border-white/10 backdrop-blur-sm">
        Global Ingress Vectors
      </div>

      {/* Threat Markers */}
      {activeThreats.map((threat) => (
        <div
          key={threat.id}
          className="absolute"
          style={{ left: `${(threat.x / 800) * 100}%`, top: `${(threat.y / 400) * 100}%` }}
        >
          <div className="relative flex items-center justify-center">
            <div className="absolute w-4 h-4 bg-danger/20 rounded-full animate-ping"></div>
            <div className="w-2 h-2 bg-danger rounded-full shadow-[0_0_8px_rgba(239,68,68,0.8)]"></div>

            <div className="absolute left-4 top-0 bg-black/80 border border-danger/30 rounded p-1.5 backdrop-blur-md min-w-[120px] pointer-events-none transform -translate-y-1/2">
              <div className="text-[9px] font-bold text-danger leading-none uppercase">{threat.type}</div>
              <div className="text-[8px] font-mono text-slate-400 mt-1">{threat.source_ip}</div>
              <div className="flex items-center gap-1 mt-1">
                <div className="w-1 h-1 bg-danger rounded-full animate-pulse"></div>
                <div className="text-[7px] text-slate-500 font-mono tracking-tighter">TRACING PATH...</div>
              </div>
            </div>
          </div>
        </div>
      ))}

      {/* Operative Note Overlay */}
      <div className="absolute top-12 right-6 max-w-[150px] transform rotate-2 pointer-events-none">
        <div className="font-hand text-[10px] text-yellow-500/50 leading-tight">
          "Looks like they're hitting us from multiple vectors today. T-Cell is handling it, but I'm keeping an eye on that Chinese cluster."
        </div>
      </div>

      {/* Decorative HUD Elements */}
      <div className="absolute bottom-4 right-4 flex flex-col gap-1 items-end pointer-events-none">
        <div className="font-mono text-[8px] text-slate-600 uppercase tracking-tighter">Nexus Satellite Link [ONLINE]</div>
        <div className="font-mono text-[8px] text-slate-600 uppercase tracking-tighter">SIGINT Confidence: 94.2%</div>
      </div>
    </div>
  );
};

export default ThreatMap;
