Run the Spring Boot backend with Docker (no Maven required):

Build and run (from repository root):

```bash
cd proxy/backend-spring
docker compose up --build
```

If using the top-level `docker-compose.yml` to run both backend and proxy (proxy requires Dockerfile changes to build Go app), run from `proxy`:

```bash
cd proxy
docker compose up --build
```

The backend will be available at `http://localhost:8081` with endpoints `/critical`, `/standard`, `/public`.
