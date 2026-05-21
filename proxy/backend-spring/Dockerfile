# Multi-stage build: build with Maven, run with lightweight JRE
FROM maven:3.9.4-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml ./
COPY src ./src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
COPY --from=builder /app/target/backend-spring-0.1.0.jar ./app.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","/app/app.jar"]
