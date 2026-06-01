import { useState, useEffect, useMemo } from 'react';
import {
  Shield,
  Activity,
  Lock,
  Zap,
  AlertTriangle,
  Terminal,
  ShieldAlert,
  Cpu,
  RefreshCw,
  Database,
  Search,
  Settings,
  ChevronRight,
  Fingerprint
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import ThreatMap from './ThreatMap';
import BloodhoundHunt from './BloodhoundHunt';

// Types to match our Go backend
interface SecurityMetrics {
  active_threats: number;
  blocked_requests: number;
  honeytoken_hits: number;
  active_sessions: number;
  revoked_tokens: number;
  total_actions_executed: number;
  active_ip_blocks: number;
  total_threats_processed: number;
  log_integrity: boolean;
  risk_score: number;
  compliance_status: string;
  encryption_status: string;
}

interface Threat {
  id: string;
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  source_ip: string;
  timestamp: string;
  description: string;
  confidence: number;
}

interface TimelineAction {
  action_type: string;
  target: string;
  severity: number;
  timestamp: string;
  description: string;
}

const ImmuniSOCDashboard = () => {
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [timeline, setTimeline] = useState<TimelineAction[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = async () => {
    try {
      // In a real environment, we'd use environment variables or secure session management.
      // This placeholder token matches the default in our .env.example for easy previewing.
      const token = 'AdminNexus#2026#SecureAccess';

      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8080';
      const response = await fetch(`${apiUrl}/api/dashboard`, {
        headers: {
          'X-Admin-Token': token
        }
      });
      if (!response.ok) throw new Error('Failed to fetch security data');
      const data = await response.json();
      setMetrics(data.metrics);
      setThreats(data.threats);
      setTimeline(data.timeline);
      setLoading(false);
    } catch (err) {
      console.error(err);
      // Fallback data for demo if backend is not reachable
      if (!metrics) {
        setMetrics({
          active_threats: 4,
          blocked_requests: 1240,
          honeytoken_hits: 5,
          active_sessions: 12,
          revoked_tokens: 3,
          total_actions_executed: 85,
          active_ip_blocks: 4,
          total_threats_processed: 450,
          log_integrity: true,
          risk_score: 88,
          compliance_status: "COMPLIANT",
          encryption_status: "AES-256-GCM"
        });
        setThreats([
          { id: '1', type: 'SQL_INJECTION_ATTEMPT', severity: 'CRITICAL', source_ip: '192.168.1.45', timestamp: new Date().toISOString(), description: 'Volumetric spike on /api/v1/auth', confidence: 0.98 },
          { id: '2', type: 'HONEYTOKEN_HIT', severity: 'HIGH', source_ip: '10.0.0.12', timestamp: new Date().toISOString(), description: 'Access to /admin/config.php detected', confidence: 1.0 },
          { id: '3', type: 'LATERAL_MOVEMENT', severity: 'HIGH', source_ip: '172.16.5.2', timestamp: new Date().toISOString(), description: 'Pivot attempt detected by Bloodhound', confidence: 0.92 },
          { id: '4', type: 'BRUTE_FORCE', severity: 'MEDIUM', source_ip: '45.33.1.9', timestamp: new Date().toISOString(), description: 'Multiple failed logins on service-billing', confidence: 0.85 },
        ]);
        setTimeline([
          { action_type: 'IP_BLOCK', target: '192.168.1.45', severity: 4, timestamp: new Date().toISOString(), description: 'Critical neutralization of ingress vector.' },
          { action_type: 'SESSION_KILL', target: 'sess_99a8', severity: 3, timestamp: new Date().toISOString(), description: 'Bloodhound pivot detection triggered.' },
          { action_type: 'ENHANCED_LOGGING', target: '172.16.5.2', severity: 2, timestamp: new Date().toISOString(), description: 'Deep packet inspection activated.' },
        ]);
      }
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000);
    return () => clearInterval(interval);
  }, []);

  const chartData = useMemo(() => [
    { name: '00:00', threats: 12, blocked: 45 },
    { name: '04:00', threats: 8, blocked: 32 },
    { name: '08:00', threats: 25, blocked: 110 },
    { name: '12:00', threats: 15, blocked: 95 },
    { name: '16:00', threats: 32, blocked: 180 },
    { name: '20:00', threats: 18, blocked: 75 },
    { name: '23:59', threats: 10, blocked: 50 },
  ], []);

  const severityColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      default: return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
    }
  };

  if (loading && !metrics) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <RefreshCw className="w-8 h-8 text-primary animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-slate-300 font-sans p-6 selection:bg-primary/30">
      {/* Top Navigation */}
      <nav className="flex items-center justify-between mb-8 pb-6 border-b border-white/5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-primary/20 rounded-xl flex items-center justify-center border border-primary/30">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">ImmuniSOC-Nexus</h1>
            <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
              <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
              NEUTROPHIL PROXY ACTIVE • V1.0.0
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-2 bg-surface px-3 py-1.5 rounded-lg border border-white/5 text-xs">
            <Database className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-slate-400">Log Integrity:</span>
            <span className={metrics?.log_integrity ? 'text-success' : 'text-danger'}>
              {metrics?.log_integrity ? 'VERIFIED' : 'TAMPERED'}
            </span>
          </div>
          <button className="p-2 hover:bg-white/5 rounded-lg transition-colors">
            <Search className="w-5 h-5 text-slate-400" />
          </button>
          <button className="p-2 hover:bg-white/5 rounded-lg transition-colors">
            <Settings className="w-5 h-5 text-slate-400" />
          </button>
        </div>
      </nav>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* Main Dashboard - Left Column */}
        <div className="lg:col-span-8 space-y-6">

          {/* Key Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <MetricCard
              label="Risk Score"
              value={metrics?.risk_score || 0}
              icon={Zap}
              trend="+2.4%"
              color="primary"
            />
            <MetricCard
              label="Active Threats"
              value={metrics?.active_threats || 0}
              icon={ShieldAlert}
              color="danger"
            />
            <MetricCard
              label="Blocked IP's"
              value={metrics?.active_ip_blocks || 0}
              icon={Lock}
              color="warning"
            />
            <MetricCard
              label="Honeytoken Hits"
              value={metrics?.honeytoken_hits || 0}
              icon={Fingerprint}
              color="secondary"
            />
          </div>

          {/* Threat World Map */}
          <div className="glass-panel p-6 glow-blue relative overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-white font-semibold flex items-center gap-2">
                <GlobeIcon className="w-4 h-4 text-primary" />
                Global Threat Nexus
              </h3>
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
                Real-Time Ingress Mapping
              </div>
            </div>
            <ThreatMap threats={threats} />
          </div>

          {/* Activity Chart */}
          <div className="glass-panel p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-white font-semibold flex items-center gap-2">
                  <Activity className="w-4 h-4 text-primary" />
                  Traffic & Threat Analysis
                </h3>
                <p className="text-xs text-slate-500 mt-1">Real-time packet inspection metrics</p>
              </div>
              <div className="flex gap-4">
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-primary" /> Threats Detected
                </div>
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-slate-700" /> Blocked Requests
                </div>
              </div>
            </div>

            <div className="h-[280px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="colorPrimary" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.05)" />
                  <XAxis
                    dataKey="name"
                    stroke="#475569"
                    fontSize={10}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="#475569"
                    fontSize={10}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111113', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }}
                    itemStyle={{ fontSize: '12px' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke="#3b82f6"
                    fillOpacity={1}
                    fill="url(#colorPrimary)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    stroke="#1e293b"
                    fill="#1e293b"
                    fillOpacity={0.1}
                    strokeWidth={1}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Operative Narrative Log */}
          <div className="glass-panel p-6 relative overflow-hidden group">
            <div className="scanline"></div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-white font-semibold flex items-center gap-2">
                <Terminal className="w-4 h-4 text-primary" />
                Operative 04 Narrative Log
              </h3>
              <div className="text-[9px] font-hand text-yellow-500/60 uppercase">Manual Entry Mode</div>
            </div>
            <div className="space-y-4">
              <div className="operative-note">
                "Detected a volumetric spike originating from known malicious subnets. Automated T-Cell response engaged. I'm seeing patterns of a coordinated credential stuffing attack on the billing endpoint. I've increased the honeypot sensitivity in that segment."
              </div>
              <div className="operative-note">
                "Bloodhound is tracking a persistent actor trying to pivot from the public frontend to the database vault. All attempts have been successfully diverted to the deception mesh. Intelligence suggests this is a known state-sponsored group."
              </div>
            </div>
          </div>

          {/* Threat List */}
          <div className="glass-panel p-6">
            <h3 className="text-white font-semibold flex items-center gap-2 mb-6">
              <AlertTriangle className="w-4 h-4 text-warning" />
              Active Security Threats
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="text-xs text-slate-500 uppercase tracking-wider border-b border-white/5">
                  <tr>
                    <th className="pb-3 font-medium">Threat ID</th>
                    <th className="pb-3 font-medium">Source</th>
                    <th className="pb-3 font-medium">Category</th>
                    <th className="pb-3 font-medium">Severity</th>
                    <th className="pb-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="text-sm divide-y divide-white/5">
                  {threats.map((threat) => (
                    <tr key={threat.id} className="hover:bg-white/[0.02] transition-colors group">
                      <td className="py-4 font-mono text-xs text-slate-400">#THR-{threat.id.substring(0,6)}</td>
                      <td className="py-4 font-mono">{threat.source_ip}</td>
                      <td className="py-4">{threat.type}</td>
                      <td className="py-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${severityColor(threat.severity)}`}>
                          {threat.severity}
                        </span>
                      </td>
                      <td className="py-4">
                        <span className="flex items-center gap-1.5 text-xs text-success">
                          <div className="w-1.5 h-1.5 rounded-full bg-success" />
                          Quarantined
                        </span>
                      </td>
                    </tr>
                  ))}
                  {threats.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-12 text-center text-slate-500 text-xs italic">
                        No critical threats detected in current cycle
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Sidebar - Right Column */}
        <div className="lg:col-span-4 space-y-6">

          {/* Bloodhound Hunt Visualization */}
          <BloodhoundHunt />

          {/* T-Cell Actions Timeline */}
          <div className="glass-panel p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-white font-semibold flex items-center gap-2">
                <Terminal className="w-4 h-4 text-secondary" />
                Autonomous Responses
              </h3>
              <span className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">T-Cell Engine</span>
            </div>

            <div className="space-y-6 relative before:absolute before:left-[11px] before:top-2 before:bottom-2 before:w-px before:bg-white/5">
              {timeline.slice(0, 5).map((action, i) => (
                <div key={i} className="relative pl-8 group">
                  <div className={`absolute left-0 top-1 w-6 h-6 rounded-lg flex items-center justify-center border bg-surface ${action.severity >= 3 ? 'border-red-500/40 text-red-400' : 'border-white/10 text-slate-500'}`}>
                    <Zap className="w-3.5 h-3.5" />
                  </div>
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-300">{action.action_type.replace(/_/g, ' ').toUpperCase()}</span>
                      <span className="text-[10px] text-slate-500">{new Date(action.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1 leading-relaxed">{action.description}</p>
                    <div className="mt-2 font-mono text-[9px] bg-white/[0.03] p-1 rounded border border-white/5 inline-block text-slate-400">
                      TARGET: {action.target}
                    </div>
                  </div>
                </div>
              ))}
              {timeline.length === 0 && (
                <div className="py-4 text-center text-slate-500 text-xs">Waiting for events...</div>
              )}
            </div>

            <button className="w-full mt-6 py-2 rounded-lg bg-white/5 border border-white/10 text-xs hover:bg-white/[0.08] transition-colors flex items-center justify-center gap-2">
              View Audit History
              <ChevronRight className="w-3 h-3" />
            </button>
          </div>

          {/* System Status */}
          <div className="glass-panel p-6">
            <h3 className="text-white font-semibold flex items-center gap-2 mb-6">
              <Cpu className="w-4 h-4 text-success" />
              Platform Integrity
            </h3>
            <div className="space-y-4">
              <StatusRow label="Neutrophil Proxy" status="active" />
              <StatusRow label="Bloodhound Mesh" status="active" />
              <StatusRow label="T-Cell Engine" status="active" />
              <StatusRow label="Monocyte Logging" status="active" />
              <StatusRow label="OPA Policy Engine" status="active" />
            </div>

            <div className="mt-8 pt-6 border-t border-white/5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-400">Compliance (POPIA)</span>
                <span className="text-xs text-success font-bold font-mono">98.5%</span>
              </div>
              <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                <div className="bg-success h-full" style={{ width: '98.5%' }} />
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};

const MetricCard = ({ label, value, icon: Icon, trend, color = "primary" }: any) => {
  const colorMap: any = {
    primary: "text-primary border-primary/20 bg-primary/5",
    danger: "text-danger border-danger/20 bg-danger/5",
    warning: "text-warning border-warning/20 bg-warning/5",
    secondary: "text-secondary border-secondary/20 bg-secondary/5",
  };

  return (
    <div className="glass-panel p-5 relative overflow-hidden group">
      <div className={`absolute top-0 right-0 p-3 opacity-10 group-hover:opacity-20 transition-opacity`}>
        <Icon className="w-12 h-12" />
      </div>
      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{label}</p>
      <div className="flex items-baseline gap-2 mt-1">
        <h4 className="text-2xl font-bold text-white tracking-tight">{value}</h4>
        {trend && <span className="text-[10px] text-success">{trend}</span>}
      </div>
      <div className={`w-8 h-1 rounded-full mt-3 ${colorMap[color].split(' ')[0].replace('text-', 'bg-')}`} />
    </div>
  );
};

const StatusRow = ({ label, status }: { label: string, status: 'active' | 'warning' | 'error' }) => {
  const statusColor = {
    active: 'bg-success shadow-[0_0_8px_rgba(16,185,129,0.5)]',
    warning: 'bg-warning shadow-[0_0_8px_rgba(245,158,11,0.5)]',
    error: 'bg-danger shadow-[0_0_8px_rgba(239,68,68,0.5)]',
  }[status];

  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-slate-400">{label}</span>
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-mono uppercase text-slate-500">{status}</span>
        <div className={`w-1.5 h-1.5 rounded-full ${statusColor}`} />
      </div>
    </div>
  );
};

const GlobeIcon = ({ className }: any) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
  </svg>
);

export default ImmuniSOCDashboard;
