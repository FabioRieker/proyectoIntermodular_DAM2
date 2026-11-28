# Imagen del backend de VulnFollowUp.
# Construir desde la carpeta backend:  docker build -t vulnfollowup-backend .

# Etapa 1: compilar el jar con Maven (los tests se ejecutan en el CI, no aquí)
FROM eclipse-temurin:21-jdk AS build
WORKDIR /build
COPY .mvn .mvn
COPY mvnw pom.xml ./
# Descargar dependencias en una capa aparte para que Docker la reutilice si solo cambia el código
RUN ./mvnw -B -q dependency:go-offline
COPY src src
RUN ./mvnw -B -q package -DskipTests

# Trivy lo usa el escáner de dependencias (POST /api/scans); se copia de la imagen oficial
FROM aquasec/trivy:0.76.2 AS trivy

# Etapa 2: imagen final, solo con el JRE, el jar y trivy
FROM eclipse-temurin:21-jre
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# Usuario sin privilegios: si alguien comprometiera la app, no sería root dentro del contenedor
RUN useradd --create-home --uid 10001 app && mkdir -p /app/audit-target && chown -R app:app /app
USER app
WORKDIR /app
COPY --from=build --chown=app:app /build/target/backend-*.jar app.jar

# El directorio a analizar se monta como volumen en /app/audit-target
ENV SCANNER_TARGET=/app/audit-target

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
