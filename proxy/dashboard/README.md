# ImmuniSOC-Nexus Dashboard

The ImmuniSOC-Nexus Dashboard is a real-time security operations center dashboard that visualizes threat intelligence, attack paths, and automated response actions from the ImmuniSOC-Nexus proxy system.

## Features

- Real-time threat visualization
- Attack path analysis with BloodHound integration
- Automated response tracking (T-Cell)
- Honeytoken engagement monitoring
- Threat severity distribution
- System health monitoring
- Emergency response controls
- IP blocking capabilities

## Prerequisites

- Node.js 16.x or higher
- npm or yarn package manager
- Access to ImmuniSOC-Nexus API backend

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd dashboard
```

2. Install dependencies:
```bash
npm install
```

3. Create environment configuration:
```bash
cp .env.example .env
```

4. Update the `.env` file with your API configuration:
```bash
REACT_APP_API_BASE_URL=https://your-api-domain.com/api
```

## Configuration

The dashboard can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| REACT_APP_API_BASE_URL | Base URL for the ImmuniSOC-Nexus API | http://localhost:8080/api |
| REACT_APP_REFRESH_INTERVAL | Data refresh interval in milliseconds | 30000 |
| REACT_APP_RETRY_ATTEMPTS | Number of retry attempts for API calls | 3 |
| REACT_APP_TIMEOUT_MS | Request timeout in milliseconds | 10000 |

## Running the Application

### Development Mode
```bash
npm start
```
The dashboard will be available at http://localhost:3000

### Production Build
```bash
npm run build
```
This creates an optimized production build in the `build` directory.

### Serving Production Build
```bash
npm install -g serve
serve -s build
```

## API Endpoints Used

The dashboard communicates with the following API endpoints:

- `/metrics` - System metrics and statistics
- `/paths` - BloodHound attack path analysis
- `/timeline` - T-Cell automated response timeline
- `/threats` - Real-time threat feed
- `/actions/emergency-response` - Trigger emergency response protocol
- `/actions/audit` - Initiate infrastructure audit
- `/actions/block-ip` - Block specified IP addresses

## Security Features

- Role-based access controls (when implemented in backend)
- Secure API communication over HTTPS
- Input validation and sanitization
- Session management (when implemented in backend)
- Audit logging of administrative actions

## Customization

The dashboard can be customized by:

1. Adding new metric cards in the `metricCards` useMemo hook
2. Creating additional panels in the dashboard grid
3. Extending the threat visualization with custom components
4. Adding new action buttons with appropriate API integrations

## Deployment

The application is built using Create React App and can be deployed to any static hosting service. For best results:

1. Build the application with `npm run build`
2. Configure your web server to serve the `build` directory
3. Ensure API endpoints are properly configured for your environment

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please contact the ImmuniSOC-Nexus development team.