# Use lightweight OpenJDK runtime
FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

# Copy application source & static assets
COPY src/ ./src/
COPY web/ ./web/
COPY test_payloads.txt ./

# Compile Java heuristic engine
RUN mkdir -p bin && javac -d bin src/CyberThreatServer.java

# Expose HTTP port
EXPOSE 8080

# Run enterprise SOC server
CMD ["java", "-cp", "bin", "CyberThreatServer"]
