App.js
import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Area,
  PieChart,
  Pie,
  Cell
} from 'recharts';

// Configuration constants
const CONFIG = {
  API_BASE_URL: process.env.REACT_APP_API_BASE_URL || 'http://localhost:8080/api',
  REFRESH_INTERVAL: parseInt(process.env.REACT_APP_REFRESH_INTERVAL) || 30000, // 30 seconds
  RETRY_ATTEMPTS: parseInt(process.env.REACT_APP_RETRY_ATTEMPTS) || 3,
  TIMEOUT_MS: parseInt(process.env.REACT_APP_TIMEOUT_MS) || 10000,
  MAX_DATA_POINTS: 50, // Limit data points to improve performance
  BATCH_SIZE: 100 // Max items to process at once
};

// Custom hook for API calls with retry logic
const useApiCall = () => {
  const abortControllersRef = useRef([]);

  const cleanupAbortedControllers = () => {
    abortControllersRef.current = abortControllersRef.current.filter(controller => !controller.signal.aborted);
  };

  const fetchWithRetry = useCallback(async (url, options = {}, retries = CONFIG.RETRY_ATTEMPTS) => {
    cleanupAbortedControllers(); // Clean up any aborted controllers
    
    for (let i = 0; i <= retries; i++) {
      try {
        const controller = new AbortController();
        abortControllersRef.current.push(controller);
        
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.TIMEOUT_MS);
        
        const response = await fetch(url, {
          ...options,
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return { data: await response.json(), ok: response.ok, timestamp: new Date() };
      } catch (error) {
        if (error.name === 'AbortError') {
          console.log(`Request to ${url} was aborted`);
          return { data: null, ok: false, error: 'Request aborted', timestamp: new Date() };
        }
        
        console.error(`Attempt ${i + 1} failed for ${url}:`, error);
        if (i === retries) {
          console.error(`All attempts failed for ${url}. Returning fallback.`);
          return { data: null, ok: false, error: error.message, timestamp: new Date() };
        }
        
        // Wait before retry with exponential backoff
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, i) * 1000));
      }
    }
  }, []);

  const fetchOrFallback = useCallback(async (endpoint, fallback) => {
    const url = `${CONFIG.API_BASE_URL}${endpoint}`;
    const result = await fetchWithRetry(url);
    
    if (result.ok && result.data) {
      return { data: result.data, ok: true, timestamp: result.timestamp };
    } else {
      console.warn(`Using fallback for ${endpoint}:`, result.error);
      return { data: fallback, ok: false, error: result.error, timestamp: new Date() };
    }
  }, [fetchWithRetry]);

  const cleanup = useCallback(() => {
    abortControllersRef.current.forEach(controller => {
      if (!controller.signal.aborted) {
        controller.abort();
      }
    });
    abortControllersRef.current = [];
  }, []);

  return { fetchWithRetry, fetchOrFallback, cleanup };
};

// Utility functions
const emptyArray = [];
const refreshIntervalMs = CONFIG.REFRESH_INTERVAL;

const severityColors = {
  CRITICAL: '#ef4444', // red-500
  HIGH: '#f97316',     // orange-500
  MEDIUM: '#eab308',   // yellow-500
  LOW: '#22c55e',      // green-500
  INFO: '#3b82f6'      // blue-500
};

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const normalizeSeverity = (severity) => {
  if (!severity) return 'INFO';
  const normalized = severity.toUpperCase();
  return severityOrder.includes(normalized) ? normalized : 'INFO';
};

const formatDateTime = (dateString) => {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  if (isNaN(date.getTime())) return 'Invalid Date';
  return date.toLocaleString();
};

const formatNumber = (num) => {
  if (typeof num !== 'number' || isNaN(num)) return num || '0';
  return new Intl.NumberFormat().format(Math.round(num));
};

const EmptyState = ({ title, message }) => (
  <div className="empty-state">
    <h3>{title}</h3>
    <p>{message}</p>
  </div>
);

// Real-world ready notification system
const showNotification = (message, type = 'info') => {
  // In a real application, this would integrate with a toast notification library
  console.log(`${type.toUpperCase()}: ${message}`);
  // Example integration with a toast library:
  // toast[type](message);
};

// Performance-optimized memoized components
const MetricCard = React.memo(({ card }) => (
  <article className={`metric-card ${card.tone}`} key={card.label}>
    <div className="metric-label">{card.label}</div>
    <div className="metric-value">{formatNumber(card.value)}</div>
    <div className="metric-detail">{card.detail}</div>
  </article>
));

const ThreatItem = React.memo(({ threat, index }) => {
  const severity = normalizeSeverity(threat.severity);
  return (
    <article className="threat-item" key={threat.id || index}>
      <div className="threat-topline">
        <span className={`severity-pill ${severity.toLowerCase()}`}>{severity}</span>
        <span className="threat-type">{threat.type || 'Threat'}</span>
        <span className="threat-ip">{threat.ip || 'Unknown IP'}</span>
        <span className="threat-time">{formatDateTime(threat.timestamp)}</span>
      </div>
      <p>{threat.description || 'No description recorded.'}</p>
    </article>
  );
});

const PathRow = React.memo(({ path, index }) => {
  const severity = normalizeSeverity(path.severity);
  return (
    <div className="path-row" key={path.id || index}>
      <div>
        <div className="path-main">
          <span>{path.source || 'Unknown source'}</span>
          <span className="path-arrow">→</span>
          <span>{path.target || 'Unknown target'}</span>
        </div>
        <div className="path-meta">
          {path.threatType || 'unknown'} - score {Number(path.score || 0).toFixed(1)} - confidence {Math.round(Number(path.confidence || 0) * 100)}%
        </div>
      </div>
      <span className={`severity-pill ${severity.toLowerCase()}`}>{severity}</span>
    </div>
  );
});

const TimelineItem = React.memo(({ action, index }) => (
  <div className="timeline-item" key={`${action.timestamp}-${index}`}>
    <div className="timeline-marker" />
    <div className="timeline-content">
      <div className="timeline-title">{action.action || 'Response Action'}</div>
      <div className="timeline-details">{action.details || 'No details recorded'}</div>
      <div className="timeline-time">{formatDateTime(action.timestamp)} - {action.target || 'Unknown target'}</div>
    </div>
  </div>
));

// Main App Component
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
  const [error, setError] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('connecting'); // connecting, connected, disconnected
  
  const { fetchOrFallback, cleanup } = useApiCall();
  const intervalRef = useRef(null);
  const mountedRef = useRef(true);

  // Cleanup function to prevent state updates on unmounted component
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
      cleanup();
    };
  }, [cleanup]);

  // Add action handlers with real-world implementations
  const handleEmergencyResponse = useCallback(async () => {
    try {
      const response = await fetch(`${CONFIG.API_BASE_URL}/actions/emergency-response`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ 
          triggered_by: 'dashboard_user', 
          timestamp: new Date().toISOString(),
          userAgent: navigator.userAgent,
          source: 'dashboard'
        })
      });
      
      if (response.ok) {
        showNotification('Emergency Response Protocol initiated successfully', 'success');
      } else {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to initiate emergency response');
      }
    } catch (err) {
      console.error('Emergency response error:', err);
      showNotification(`Failed to initiate emergency response: ${err.message}`, 'error');
    }
  }, []);

  const handleInfrastructureAudit = useCallback(async () => {
    try {
      const response = await fetch(`${CONFIG.API_BASE_URL}/actions/audit`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ 
          triggered_by: 'dashboard_user', 
          timestamp: new Date().toISOString(),
          userAgent: navigator.userAgent,
          source: 'dashboard'
        })
      });
      
      if (response.ok) {
        showNotification('Infrastructure Audit initiated successfully', 'success');
      } else {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to initiate infrastructure audit');
      }
    } catch (err) {
      console.error('Infrastructure audit error:', err);
      showNotification(`Failed to initiate infrastructure audit: ${err.message}`, 'error');
    }
  }, []);

  const handleBlockIP = useCallback(async (ipAddress = null) => {
    try {
      const ipToBlock = ipAddress || prompt('Enter IP address to block:');
      if (!ipToBlock) return;
      
      // Validate IP address format
      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      if (!ipRegex.test(ipToBlock)) {
        showNotification('Invalid IP address format', 'error');
        return;
      }
      
      const response = await fetch(`${CONFIG.API_BASE_URL}/actions/block-ip`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ 
          ip_address: ipToBlock, 
          triggered_by: 'dashboard_user', 
          timestamp: new Date().toISOString(),
          source: 'dashboard'
        })
      });
      
      if (response.ok) {
        showNotification(`IP ${ipToBlock} blocked successfully`, 'success');
      } else {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to block IP address');
      }
    } catch (err) {
      console.error('Block IP error:', err);
      showNotification(`Failed to block IP address: ${err.message}`, 'error');
    }
  }, []);

  // Enhanced data fetching with better error handling and performance optimization
  const fetchDashboardData = useCallback(async () => {
    if (!mountedRef.current) return; // Early return if component is unmounted
    
    setIsLoading(true);
    setError(null);
    
    try {
      const [metricsResult, pathsResult, timelineResult, threatsResult] = await Promise.allSettled([
        fetchOrFallback('/metrics', {}),
        fetchOrFallback('/paths', emptyArray),
        fetchOrFallback('/timeline', emptyArray),
        fetchOrFallback('/threats', emptyArray),
      ]);

      // Process results only if component is still mounted
      if (!mountedRef.current) return;
      
      const metricsData = metricsResult.status === 'fulfilled' ? metricsResult.value : { data: {}, ok: false };
      const pathsData = pathsResult.status === 'fulfilled' ? pathsResult.value : { data: emptyArray, ok: false };
      const timelineData = timelineResult.status === 'fulfilled' ? timelineResult.value : { data: emptyArray, ok: false };
      const threatsData = threatsResult.status === 'fulfilled' ? threatsResult.value : { data: emptyArray, ok: false };

      // Limit data size for performance
      const limitedPaths = Array.isArray(pathsData.data) 
        ? pathsData.data.slice(0, CONFIG.BATCH_SIZE) 
        : emptyArray;
      const limitedTimeline = Array.isArray(timelineData.data) 
        ? timelineData.data.slice(0, CONFIG.BATCH_SIZE) 
        : emptyArray;
      const limitedThreats = Array.isArray(threatsData.data) 
        ? threatsData.data.slice(0, CONFIG.BATCH_SIZE) 
        : emptyArray;

      setMetrics(metricsData.data || {});
      setBloodhoundPaths(limitedPaths);
      setContainmentTimeline(limitedTimeline);
      setThreats(limitedThreats);
      
      setApiHealth({
        metrics: metricsData.ok,
        paths: pathsData.ok,
        timeline: timelineData.ok,
        threats: threatsData.ok,
      });

      // Update connection status based on health
      const allHealthy = Object.values({
        metrics: metricsData.ok,
        paths: pathsData.ok,
        timeline: timelineData.ok,
        threats: threatsData.ok,
      }).every(status => status);
      
      setConnectionStatus(allHealthy ? 'connected' : 'disconnected');

      setLastUpdated(new Date());
      
      // Only update loading state if component is still mounted
      if (mountedRef.current) {
        setIsLoading(false);
      }
      
      // Log any individual failures
      if (!metricsData.ok) console.warn('Metrics API failed:', metricsData.error);
      if (!pathsData.ok) console.warn('Paths API failed:', pathsData.error);
      if (!timelineData.ok) console.warn('Timeline API failed:', timelineData.error);
      if (!threatsData.ok) console.warn('Threats API failed:', threatsData.error);
    } catch (err) {
      if (!mountedRef.current) return;
      
      console.error('Error fetching dashboard data:', err);
      setError(err.message);
      setIsLoading(false);
      setConnectionStatus('disconnected');
      showNotification('Failed to fetch dashboard data. Check connection and try again.', 'error');
    }
  }, [fetchOrFallback]);

  // Initialize data and set up polling
  useEffect(() => {
    fetchDashboardData();

    intervalRef.current = setInterval(() => {
      if (mountedRef.current) {
        fetchDashboardData();
      }
    }, refreshIntervalMs);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [fetchDashboardData]);

  // Memoized calculations
  const activeThreats = useMemo(() => metrics.activeThreats ?? metrics.total_threats_processed ?? 0, [metrics]);
  const blockedRequests = useMemo(() => metrics.blockedRequests ?? metrics.total_ip_blocks ?? 0, [metrics]);
  const honeytokenHits = useMemo(() => metrics.honeytokenHits ?? 0, [metrics]);
  const activeSessions = useMemo(() => metrics.activeSessions ?? metrics.active_sessions ?? 0, [metrics]);
  const revokedTokens = useMemo(() => metrics.totalTokensRevoked ?? metrics.total_tokens_revoked ?? 0, [metrics]);
  const totalActions = useMemo(() => metrics.totalActionsExecuted ?? metrics.total_actions_executed ?? 0, [metrics]);

  // Calculate overall security status based on metrics
  const securityStatus = useMemo(() => {
    if (activeThreats > 10) {
      return { level: 'critical', message: 'Critical security events detected' };
    } else if (activeThreats > 5) {
      return { level: 'high', message: 'Multiple security events detected' };
    } else if (activeThreats > 0) {
      return { level: 'medium', message: 'Security events detected' };
    } else {
      return { level: 'low', message: 'Normal security operations' };
    }
  }, [activeThreats]);

  // Calculate infrastructure status
  const infraStatus = useMemo(() => {
    const totalComponents = Object.keys(apiHealth).length;
    const healthyComponents = Object.values(apiHealth).filter(status => status).length;
    
    const blockedPercentage = totalActions > 0 ? Math.round((blockedRequests / totalActions) * 100) : 0;
    
    return {
      componentsHealthy: healthyComponents,
      totalComponents,
      healthPercentage: Math.round((healthyComponents / totalComponents) * 100),
      blockedPercentage,
      honeytokenEngagement: honeytokenHits > 0 ? 'Active' : 'Monitoring',
      sessionActivity: activeSessions > 0 ? 'Active' : 'Stable'
    };
  }, [apiHealth, blockedRequests, totalActions, honeytokenHits, activeSessions]);

  const latestThreat = useMemo(() => threats[0], [threats]);

  const sortedPaths = useMemo(() => {
    return [...bloodhoundPaths].sort((a, b) => {
      const severityA = normalizeSeverity(a.severity);
      const severityB = normalizeSeverity(b.severity);
      return severityOrder.indexOf(severityA) - severityOrder.indexOf(severityB);
    });
  }, [bloodhoundPaths]);

  const severityData = useMemo(() => {
    const severityCounts = {};
    bloodhoundPaths.forEach((path) => {
      const severity = normalizeSeverity(path.severity);
      if (severityCounts[severity]) {
        severityCounts[severity]++;
      } else {
        severityCounts[severity] = 1;
      }
    });

    return Object.entries(severityCounts).map(([name, value]) => ({ name, value }));
  }, [bloodhoundPaths]);

  const activityData = useMemo(() => {
    const activityCounts = {};
    containmentTimeline.forEach((action) => {
      const date = new Date(action.timestamp).toLocaleDateString();
      if (activityCounts[date]) {
        activityCounts[date]++;
      } else {
        activityCounts[date] = 1;
      }
    });

    // Limit data points for chart performance
    const entries = Object.entries(activityCounts).slice(0, CONFIG.MAX_DATA_POINTS);
    return entries.map(([name, value]) => ({ name, threats: value }));
  }, [containmentTimeline]);

  const metricCards = useMemo(() => {
    return [
      {
        label: 'Active Threats',
        value: activeThreats,
        detail: latestThreat ? `Latest: ${latestThreat.type} - ${formatDateTime(latestThreat.timestamp)}` : 'No active threats',
        tone: 'critical',
      },
      {
        label: 'Blocked Requests',
        value: blockedRequests,
        detail: `${infraStatus.blockedPercentage}% of total actions`,
        tone: 'warning',
      },
      {
        label: 'Honeytoken Hits',
        value: honeytokenHits,
        detail: `${infraStatus.honeytokenEngagement}`,
        tone: 'info',
      },
      {
        label: 'Active Sessions',
        value: activeSessions,
        detail: `${infraStatus.sessionActivity}`,
        tone: 'info',
      },
      {
        label: 'Revoked Tokens',
        value: revokedTokens,
        detail: 'Recent token revocation actions',
        tone: 'info',
      },
      {
        label: 'Total Actions',
        value: totalActions,
        detail: 'Automated responses executed',
        tone: 'info',
      }
    ];
  }, [
    activeThreats,
    blockedRequests,
    honeytokenHits,
    activeSessions,
    revokedTokens,
    totalActions,
    latestThreat,
    infraStatus,
  ]);

  // Connection status indicator
  const getConnectionStatusIndicator = useCallback(() => {
    switch (connectionStatus) {
      case 'connected':
        return { text: 'Connected', className: 'status-dot online' };
      case 'disconnected':
        return { text: 'Disconnected', className: 'status-dot degraded' };
      default:
        return { text: 'Connecting...', className: 'status-dot' };
    }
  }, [connectionStatus]);

  const statusIndicator = getConnectionStatusIndicator();

  return (
    <div className="App">
      <header className="app-header">
        <div>
          <p className="eyebrow">IMMUNISOC-NEXUS</p>
          <h1>Security Operations Center Dashboard</h1>
        </div>
        <div className="status-strip" aria-live="polite">
          <div className={`security-status ${securityStatus.level}`}>
            <span className="status-dot" />
            <span>{securityStatus.message}</span>
          </div>
          <div className="connection-status">
            <span className={statusIndicator.className} />
            <span>{statusIndicator.text}</span>
          </div>
          <div className="quick-actions">
            <button className="quick-action-btn emergency" onClick={handleEmergencyResponse}>
              EMERGENCY RESPONSE
            </button>
            <button className="quick-action-btn" onClick={handleInfrastructureAudit}>
              INFRA AUDIT
            </button>
            <button className="quick-action-btn" onClick={() => handleBlockIP()}>
              BLOCK IP
            </button>
          </div>
          <span className="status-time">{lastUpdated ? `Updated ${formatDateTime(lastUpdated)}` : 'Sync pending'}</span>
        </div>
      </header>

      <main className="dashboard-container">
        {error && (
          <div className="error-banner">
            <div className="security-alert">
              <span>Error: {error}</span>
            </div>
          </div>
        )}

        {isLoading && (
          <div className="loading-indicator">
            <div className="spinner"></div>
            <p>Loading security data...</p>
          </div>
        )}

        <section className="infra-status-grid">
          <div className="infra-status-card">
            <div className="infra-status-header">
              <div className={`infra-status-icon ${infraStatus.healthPercentage > 80 ? 'ok' : infraStatus.healthPercentage > 50 ? 'warning' : 'critical'}`}>
                ✓
              </div>
              <div>
                <h3 className="infra-status-title">System Health</h3>
                <p className="infra-status-desc">Components operational</p>
              </div>
            </div>
            <div className="infra-status-value">{infraStatus.healthPercentage}%</div>
          </div>
          
          <div className="infra-status-card">
            <div className="infra-status-header">
              <div className={`infra-status-icon ${infraStatus.blockedPercentage > 0 ? 'warning' : 'ok'}`}>
                🛡️
              </div>
              <div>
                <h3 className="infra-status-title">Threat Mitigation</h3>
                <p className="infra-status-desc">Requests blocked</p>
              </div>
            </div>
            <div className="infra-status-value">{infraStatus.blockedPercentage}%</div>
          </div>
          
          <div className="infra-status-card">
            <div className="infra-status-header">
              <div className={`infra-status-icon ${infraStatus.honeytokenEngagement === 'Active' ? 'warning' : 'ok'}`}>
                🍯
              </div>
              <div>
                <h3 className="infra-status-title">Deception Layer</h3>
                <p className="infra-status-desc">Honeytoken engagement</p>
              </div>
            </div>
            <div className="infra-status-value">{infraStatus.honeytokenEngagement}</div>
          </div>
          
          <div className="infra-status-card">
            <div className="infra-status-header">
              <div className={`infra-status-icon ${infraStatus.sessionActivity === 'Active' ? 'warning' : 'ok'}`}>
                👤
              </div>
              <div>
                <h3 className="infra-status-title">Session Activity</h3>
                <p className="infra-status-desc">Active sessions</p>
              </div>
            </div>
            <div className="infra-status-value">{infraStatus.sessionActivity}</div>
          </div>
        </section>

        <section className="metrics-grid" aria-label="Security metrics">
          {metricCards.map((card) => (
            <MetricCard card={card} key={card.label} />
          ))}
        </section>

        <section className="dashboard-grid">
          <div className="panel chart-panel wide">
            <div className="panel-header">
              <div>
                <h2>Threat Activity Timeline</h2>
                <p>Real-time threat detection and response activities.</p>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={activityData}>
                <defs>
                  <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#374151" strokeDasharray="3 3" />
                <XAxis dataKey="name" tickLine={{ stroke: '#9ca3af' }} axisLine={{ stroke: '#374151' }} tick={{ fill: '#9ca3af' }} />
                <YAxis allowDecimals={false} tickLine={{ stroke: '#9ca3af' }} axisLine={{ stroke: '#374151' }} tick={{ fill: '#9ca3af' }} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1f2937', 
                    borderColor: '#374151', 
                    color: '#f9fafb',
                    borderRadius: '8px',
                    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.3)'
                  }} 
                />
                <Area type="monotone" dataKey="threats" stroke="#3b82f6" strokeWidth={2} fill="url(#activityFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="panel chart-panel">
            <div className="panel-header">
              <div>
                <h2>Threat Severity Distribution</h2>
                <p>Current threat landscape by severity level.</p>
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
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#1f2937', 
                      borderColor: '#374151', 
                      color: '#f9fafb',
                      borderRadius: '8px',
                      boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.3)'
                    }} 
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No Severity Data" message="Threat severity appears here once detections arrive." />
            )}
          </div>

          <div className="panel wide">
            <div className="panel-header">
              <div>
                <h2>BloodHound Attack Path Analysis</h2>
                <p>Critical pathways identified by deception tracking.</p>
              </div>
              <span className="count-badge">{sortedPaths.length}</span>
            </div>
            {sortedPaths.length > 0 ? (
              <div className="paths-table">
                {sortedPaths.map((path, index) => (
                  <PathRow path={path} index={index} key={path.id || index} />
                ))}
              </div>
            ) : (
              <EmptyState title="No Attack Paths Detected" message="BloodHound has not identified high-risk movement." />
            )}
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h2>T-Cell Automated Responses</h2>
                <p>Recent self-healing actions executed by the system.</p>
              </div>
              <span className="count-badge">{containmentTimeline.length}</span>
            </div>
            {containmentTimeline.length > 0 ? (
              <div className="timeline">
                {containmentTimeline.slice(0, 8).map((action, index) => (
                  <TimelineItem action={action} index={index} key={`${action.timestamp}-${index}`} />
                ))}
              </div>
            ) : (
              <EmptyState title="No Containment Actions" message="T-Cell response actions will populate this panel." />
            )}
          </div>

          <div className="panel wide">
            <div className="panel-header">
              <div>
                <h2>Real-Time Threat Feed</h2>
                <p>Live threat intelligence from proxy sensors.</p>
              </div>
              <span className="count-badge">{threats.length}</span>
            </div>
            {threats.length > 0 ? (
              <div className="threat-list">
                {threats.slice(0, 8).map((threat, index) => (
                  <ThreatItem threat={threat} index={index} key={threat.id || index} />
                ))}
              </div>
            ) : (
              <EmptyState title={isLoading ? 'Loading Threat Feed' : 'No Recent Threats'} message={isLoading ? 'Collecting proxy telemetry...' : 'The recent threat feed is clear.'} />
            )}
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h2>System Health Status</h2>
                <p>Component availability and performance.</p>
              </div>
            </div>
            <div className="health-list">
              {Object.entries(apiHealth).map(([name, ok]) => (
                <div className="health-row" key={name}>
                  <span>{name.charAt(0).toUpperCase() + name.slice(1)}</span>
                  <span className={`health-state ${ok ? 'ok' : 'fail'}`}>{ok ? 'Operational' : 'Offline'}</span>
                </div>
              ))}
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;