import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const api = axios.create({
  baseURL: process.env.REACT_APP_PROXY_URL || 'http://localhost:8080',
});

const emptyArray = [];

async function fetchOrFallback(path, fallback) {
  try {
    const response = await api.get(path);
    return response.data;
  } catch (error) {
    console.error(`Error fetching ${path}:`, error);
    return fallback;
  }
}

function App() {
  const [metrics, setMetrics] = useState({});
  const [bloodhoundPaths, setBloodhoundPaths] = useState([]);
  const [containmentTimeline, setContainmentTimeline] = useState([]);
  const [threats, setThreats] = useState([]);

  // Fetch metrics from the proxy
  useEffect(() => {
    const fetchMetrics = async () => {
      const [metricsData, pathsData, timelineData, threatsData] = await Promise.all([
        fetchOrFallback('/metrics', {}),
        fetchOrFallback('/api/paths', emptyArray),
        fetchOrFallback('/api/timeline', emptyArray),
        fetchOrFallback('/api/threats', emptyArray),
      ]);

      setMetrics(metricsData);
      setBloodhoundPaths(Array.isArray(pathsData) ? pathsData : emptyArray);
      setContainmentTimeline(Array.isArray(timelineData) ? timelineData : emptyArray);
      setThreats(Array.isArray(threatsData) ? threatsData : emptyArray);
    };

    fetchMetrics();
    
    // Refresh data every 30 seconds
    const interval = setInterval(fetchMetrics, 30000);
    return () => clearInterval(interval);
  }, []);

  // Mock data for charts until we have real API endpoints
  const threatData = [
    { name: 'Mon', threats: 4 },
    { name: 'Tue', threats: 3 },
    { name: 'Wed', threats: 8 },
    { name: 'Thu', threats: 6 },
    { name: 'Fri', threats: 12 },
    { name: 'Sat', threats: 9 },
    { name: 'Sun', threats: 7 },
  ];

  const threatTypeData = [
    { name: 'Brute Force', value: 35 },
    { name: 'SQL Injection', value: 20 },
    { name: 'XSS', value: 15 },
    { name: 'Lateral Movement', value: 12 },
    { name: 'Exfiltration', value: 10 },
    { name: 'Other', value: 8 },
  ];

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D'];

  return (
    <div className="App">
      <header className="app-header">
        <h1>ImmuniSOC-Nexus Dashboard</h1>
        <p>Real-time Security Monitoring & Analytics</p>
      </header>

      <div className="dashboard-container">
        {/* Metrics Cards */}
        <div className="metrics-grid">
          <div className="metric-card">
            <h3>Active Threats</h3>
            <p className="metric-value">{metrics.activeThreats ?? metrics.total_threats_processed ?? 0}</p>
          </div>
          <div className="metric-card">
            <h3>Blocked Requests</h3>
            <p className="metric-value">{metrics.blockedRequests ?? metrics.total_ip_blocks ?? 0}</p>
          </div>
          <div className="metric-card">
            <h3>Honeytoken Hits</h3>
            <p className="metric-value">{metrics.honeytokenHits ?? 0}</p>
          </div>
          <div className="metric-card">
            <h3>Active Sessions</h3>
            <p className="metric-value">{metrics.activeSessions ?? metrics.active_sessions ?? 0}</p>
          </div>
        </div>

        {/* Charts Section */}
        <div className="charts-section">
          <div className="chart-container">
            <h2>Threat Activity Over Time</h2>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={threatData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="threats" stroke="#8884d8" activeDot={{ r: 8 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div className="chart-container">
            <h2>Threat Type Distribution</h2>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={threatTypeData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                >
                  {threatTypeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Bloodhound Paths Visualization */}
        <div className="section">
          <h2>Bloodhound Attack Paths</h2>
          <div className="paths-list">
            {bloodhoundPaths.length > 0 ? (
              bloodhoundPaths.map((path, index) => (
                <div key={index} className="path-item">
                  <span className="path-source">{path.source}</span>
                  <span className="path-arrow">-&gt;</span>
                  <span className="path-target">{path.target}</span>
                  <span className={`path-severity ${(path.severity || 'low').toLowerCase()}`}>{path.severity || 'LOW'}</span>
                </div>
              ))
            ) : (
              <p>No attack paths detected</p>
            )}
          </div>
        </div>

        {/* Containment Timeline */}
        <div className="section">
          <h2>Containment Actions Timeline</h2>
          <div className="timeline">
            {containmentTimeline.length > 0 ? (
              containmentTimeline.map((action, index) => (
                <div key={index} className="timeline-item">
                  <div className="timeline-time">{action.timestamp}</div>
                  <div className="timeline-content">
                    <strong>{action.action}</strong> on {action.target}
                    <div className="timeline-details">{action.details}</div>
                  </div>
                </div>
              ))
            ) : (
              <p>No containment actions recorded</p>
            )}
          </div>
        </div>

        {/* Recent Threats */}
        <div className="section">
          <h2>Recent Threats</h2>
          <div className="threats-list">
            {threats.length > 0 ? (
              threats.map((threat, index) => (
                <div key={index} className="threat-item">
                  <div className="threat-header">
                    <span className={`threat-type ${(threat.type || 'other').toLowerCase()}`}>{threat.type || 'Other'}</span>
                    <span className="threat-ip">{threat.ip}</span>
                    <span className="threat-time">{threat.timestamp}</span>
                  </div>
                  <div className="threat-details">{threat.description}</div>
                </div>
              ))
            ) : (
              <p>No recent threats detected</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
