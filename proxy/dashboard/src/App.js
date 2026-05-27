import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import './App.css';

import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const api = axios.create({
  baseURL: process.env.REACT_APP_PROXY_URL || 'http://localhost:8080',
});

const emptyArray = [];
const refreshIntervalMs = 30000;

const severityOrder = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const severityColors = {
  CRITICAL: '#d92d20',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#16a34a',
  INFO: '#2563eb',
};

async function fetchOrFallback(path, fallback) {
  try {
    const response = await api.get(path);
    return { data: response.data, ok: true };
  } catch (error) {
    console.error(`Error fetching ${path}:`, error);
    return { data: fallback, ok: false };
  }
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function formatDateTime(value) {
  if (!value) {
    return 'Not recorded';
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function normalizeSeverity(value) {
  return String(value || 'INFO').toUpperCase();
}

function App() {
  const [metrics, setMetrics] = useState({});
  const [bloodhoundPaths, setBloodhoundPaths] = useState([]);
  const [containmentTimeline, setContainmentTimeline] = useState([]);
  const [threats, setThreats] = useState([]);
  const [apiHealth, setApiHealth] = useState({
    metrics: false,
    paths: false,
    timeline: false,
    threats: false,
  });
  const [lastUpdated, setLastUpdated] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchDashboardData = async () => {
      const [metricsResult, pathsResult, timelineResult, threatsResult] = await Promise.all([
        fetchOrFallback('/metrics', {}),
        fetchOrFallback('/api/paths', emptyArray),
        fetchOrFallback('/api/timeline', emptyArray),
        fetchOrFallback('/api/threats', emptyArray),
      ]);

      setMetrics(metricsResult.data || {});
      setBloodhoundPaths(Array.isArray(pathsResult.data) ? pathsResult.data : emptyArray);
      setContainmentTimeline(Array.isArray(timelineResult.data) ? timelineResult.data : emptyArray);
      setThreats(Array.isArray(threatsResult.data) ? threatsResult.data : emptyArray);
      setApiHealth({
        metrics: metricsResult.ok,
        paths: pathsResult.ok,
        timeline: timelineResult.ok,
        threats: threatsResult.ok,
      });
      setLastUpdated(new Date());
      setIsLoading(false);
    };

    fetchDashboardData();

    const interval = setInterval(fetchDashboardData, refreshIntervalMs);
    return () => clearInterval(interval);
  }, []);

  const activeThreats = metrics.activeThreats ?? metrics.total_threats_processed ?? 0;
  const blockedRequests = metrics.blockedRequests ?? metrics.total_ip_blocks ?? 0;
  const honeytokenHits = metrics.honeytokenHits ?? 0;
  const activeSessions = metrics.activeSessions ?? metrics.active_sessions ?? 0;
  const revokedTokens = metrics.totalTokensRevoked ?? metrics.total_tokens_revoked ?? 0;
  const totalActions = metrics.totalActionsExecuted ?? metrics.total_actions_executed ?? 0;

  const healthOnline = Object.values(apiHealth).every(Boolean);
  const latestThreat = threats[0];

  const severityData = useMemo(() => {
    const counts = threats.reduce((acc, threat) => {
      const severity = normalizeSeverity(threat.severity);
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {});

    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => (severityOrder[b.name] || 0) - (severityOrder[a.name] || 0));
  }, [threats]);

  const activityData = useMemo(() => {
    const counts = {};

    threats.forEach((threat) => {
      const parsed = new Date(threat.timestamp);
      const label = Number.isNaN(parsed.getTime())
        ? 'Unknown'
        : parsed.toLocaleDateString([], { month: 'short', day: '2-digit' });
      counts[label] = (counts[label] || 0) + 1;
    });

    const entries = Object.entries(counts).map(([name, value]) => ({ name, threats: value }));
    if (entries.length > 0) {
      return entries.slice(-7);
    }

    return [
      { name: 'Now', threats: Number(activeThreats) || 0 },
      { name: 'Blocked', threats: Number(blockedRequests) || 0 },
      { name: 'Honey', threats: Number(honeytokenHits) || 0 },
    ];
  }, [activeThreats, blockedRequests, honeytokenHits, threats]);

  const sortedPaths = useMemo(() => {
    return [...bloodhoundPaths].sort((a, b) => {
      const severityDiff = (severityOrder[normalizeSeverity(b.severity)] || 0) - (severityOrder[normalizeSeverity(a.severity)] || 0);
      if (severityDiff !== 0) {
        return severityDiff;
      }
      return Number(b.score || 0) - Number(a.score || 0);
    });
  }, [bloodhoundPaths]);

  const metricCards = [
    {
      label: 'Active Threats',
      value: activeThreats,
      tone: activeThreats > 0 ? 'danger' : 'steady',
      detail: latestThreat ? `${latestThreat.type || 'Threat'} last seen ${formatDateTime(latestThreat.timestamp)}` : 'No active detections in the feed',
    },
    {
      label: 'Blocked Requests',
      value: blockedRequests,
      tone: blockedRequests > 0 ? 'warning' : 'steady',
      detail: `${formatNumber(totalActions)} automated response actions`,
    },
    {
      label: 'Honeytoken Hits',
      value: honeytokenHits,
      tone: honeytokenHits > 0 ? 'danger' : 'steady',
      detail: honeytokenHits > 0 ? 'Deception layer has been touched' : 'No deception hits recorded',
    },
    {
      label: 'Active Sessions',
      value: activeSessions,
      tone: 'info',
      detail: `${formatNumber(revokedTokens)} revoked tokens currently tracked`,
    },
  ];

  return (
    <div className="App">
      <header className="app-header">
        <div>
          <p className="eyebrow">ImmuniSOC-Nexus</p>
          <h1>Security Operations Dashboard</h1>
        </div>
        <div className="status-strip" aria-live="polite">
          <span className={`status-dot ${healthOnline ? 'online' : 'degraded'}`} />
          <span>{healthOnline ? 'Proxy telemetry online' : 'Telemetry degraded'}</span>
          <span className="status-time">{lastUpdated ? `Updated ${formatDateTime(lastUpdated)}` : 'Sync pending'}</span>
        </div>
      </header>

      <main className="dashboard-container">
        <section className="metrics-grid" aria-label="Security metrics">
          {metricCards.map((card) => (
            <article className={`metric-card ${card.tone}`} key={card.label}>
              <div className="metric-label">{card.label}</div>
              <div className="metric-value">{formatNumber(card.value)}</div>
              <div className="metric-detail">{card.detail}</div>
            </article>
          ))}
        </section>

        <section className="dashboard-grid">
          <div className="panel chart-panel wide">
            <div className="panel-header">
              <div>
                <h2>Threat Activity</h2>
                <p>Recent detections grouped from the live threat feed.</p>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={activityData}>
                <defs>
                  <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#2563eb" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#2563eb" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#dbe4ee" strokeDasharray="3 3" />
                <XAxis dataKey="name" tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
                <Tooltip />
                <Area type="monotone" dataKey="threats" stroke="#2563eb" strokeWidth={2} fill="url(#activityFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="panel chart-panel">
            <div className="panel-header">
              <div>
                <h2>Severity Mix</h2>
                <p>Current threat distribution by severity.</p>
              </div>
            </div>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={58} outerRadius={92} paddingAngle={3}>
                    {severityData.map((entry) => (
                      <Cell key={entry.name} fill={severityColors[entry.name] || severityColors.INFO} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No severity data" message="Threat severity appears here once detections arrive." />
            )}
          </div>

          <div className="panel wide">
            <div className="panel-header">
              <div>
                <h2>Bloodhound Attack Paths</h2>
                <p>High-risk paths discovered by request tracking.</p>
              </div>
              <span className="count-badge">{sortedPaths.length}</span>
            </div>
            {sortedPaths.length > 0 ? (
              <div className="paths-table">
                {sortedPaths.map((path, index) => {
                  const severity = normalizeSeverity(path.severity);
                  return (
                    <div className="path-row" key={path.id || index}>
                      <div>
                        <div className="path-main">
                          <span>{path.source || 'Unknown source'}</span>
                          <span className="path-arrow">-&gt;</span>
                          <span>{path.target || 'Unknown target'}</span>
                        </div>
                        <div className="path-meta">
                          {path.threatType || 'unknown'} - score {Number(path.score || 0).toFixed(1)} - confidence {Math.round(Number(path.confidence || 0) * 100)}%
                        </div>
                      </div>
                      <span className={`severity-pill ${severity.toLowerCase()}`}>{severity}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <EmptyState title="No attack paths detected" message="Bloodhound has not identified high-risk movement." />
            )}
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h2>Containment Actions</h2>
                <p>Recent T-Cell automated responses.</p>
              </div>
              <span className="count-badge">{containmentTimeline.length}</span>
            </div>
            {containmentTimeline.length > 0 ? (
              <div className="timeline">
                {containmentTimeline.slice(0, 8).map((action, index) => (
                  <div className="timeline-item" key={`${action.timestamp}-${index}`}>
                    <div className="timeline-marker" />
                    <div className="timeline-content">
                      <div className="timeline-title">{action.action || 'response_action'}</div>
                      <div className="timeline-details">{action.details || 'No details recorded'}</div>
                      <div className="timeline-time">{formatDateTime(action.timestamp)} - {action.target || 'unknown target'}</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="No containment yet" message="T-Cell response actions will populate this panel." />
            )}
          </div>

          <div className="panel wide">
            <div className="panel-header">
              <div>
                <h2>Recent Threats</h2>
                <p>Latest detections from the proxy threat feed.</p>
              </div>
              <span className="count-badge">{threats.length}</span>
            </div>
            {threats.length > 0 ? (
              <div className="threat-list">
                {threats.slice(0, 8).map((threat, index) => {
                  const severity = normalizeSeverity(threat.severity);
                  return (
                    <article className="threat-item" key={threat.id || index}>
                      <div className="threat-topline">
                        <span className={`severity-pill ${severity.toLowerCase()}`}>{severity}</span>
                        <span className="threat-type">{threat.type || 'Threat'}</span>
                        <span className="threat-ip">{threat.ip || 'unknown ip'}</span>
                        <span className="threat-time">{formatDateTime(threat.timestamp)}</span>
                      </div>
                      <p>{threat.description || 'No description recorded.'}</p>
                    </article>
                  );
                })}
              </div>
            ) : (
              <EmptyState title={isLoading ? 'Loading threat feed' : 'No recent threats'} message={isLoading ? 'Collecting proxy telemetry.' : 'The recent threat feed is clear.'} />
            )}
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h2>Telemetry Health</h2>
                <p>Endpoint availability for dashboard data.</p>
              </div>
            </div>
            <div className="health-list">
              {Object.entries(apiHealth).map(([name, ok]) => (
                <div className="health-row" key={name}>
                  <span>{name}</span>
                  <span className={`health-state ${ok ? 'ok' : 'fail'}`}>{ok ? 'online' : 'offline'}</span>
                </div>
              ))}
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

function EmptyState({ title, message }) {
  return (
    <div className="empty-state">
      <div className="empty-title">{title}</div>
      <p>{message}</p>
    </div>
  );
}

export default App;
