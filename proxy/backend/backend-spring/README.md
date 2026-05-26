# ImmuniSOC-Nexus - Mock Tier Backend (Spring Boot)

This is a minimal Spring Boot application that exposes three endpoints used by the Neutrophil proxy:

- `/critical` - Critical tier
- `/standard` - Standard tier
- `/public` - Public tier

Run with Java 17 and Maven:

```bash
cd proxy/backend-spring
mvn spring-boot:run
```

Or build and run jar:

```bash
cd proxy/backend-spring
mvn -DskipTests package
java -jar target/backend-spring-0.1.0.jar
```

Then the proxy can forward to `http://localhost:8081/critical`, etc.
