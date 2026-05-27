# ImmuniSOC-Nexus Dashboard

The ImmuniSOC-Nexus Dashboard provides real-time security monitoring and analytics for the cybersecurity platform.

## Features

- **Real-time Metrics**: View current security metrics including active threats, blocked requests, and honeytoken hits
- **Threat Visualization**: Interactive charts showing threat activity over time and threat type distribution
- **Bloodhound Path Tracking**: Visual representation of attack paths detected by the Bloodhound module
- **Containment Timeline**: Chronological view of automated containment actions taken by the T-Cell engine
- **Threat Monitoring**: Detailed view of recent security threats with classifications and details

## Getting Started

### Prerequisites

- Node.js 16 or higher
- npm or yarn package manager

### Installation

1. Navigate to the dashboard directory:
```bash
cd dashboard
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

4. Open your browser to `http://localhost:3000`

### Production Build

To create a production-ready build:
```bash
npm run build
```

## Configuration

The dashboard connects to the ImmuniSOC-Nexus proxy at `http://localhost:8080` by default. The proxy should expose the following endpoints:

- `/metrics` - System metrics
- `/api/paths` - Bloodhound attack paths
- `/api/timeline` - Containment actions timeline
- `/api/threats` - Recent threats data

## Components

- **React 18** - Frontend library
- **Recharts** - Data visualization
- **Axios** - HTTP client for API communication
- **Bootstrap-compatible CSS** - Styling framework

## Security Monitoring Capabilities

The dashboard visualizes data from multiple security modules:

1. **Neutrophil Proxy Membrane** - Traffic filtering and authentication
2. **BloodHound Tracker** - Network topology and attack path visualization
3. **T-Cell Self-Healing Engine** - Automated response actions
4. **Deception Generator** - Honeytoken and decoy detection
5. **Monocyte Immutable Logging** - Cryptographic log integrity

## Usage

The dashboard automatically refreshes data every 30 seconds. Key visualizations include:

- Metrics cards showing current security status
- Line chart of threat activity over time
- Pie chart of threat type distribution
- List of detected attack paths
- Timeline of containment actions
- Recent threats with classifications

## Testing

Run the test suite:
```bash
npm test
```

## Contributing

Contributions to enhance the dashboard's capabilities are welcome. Please follow the contribution guidelines in the main repository.