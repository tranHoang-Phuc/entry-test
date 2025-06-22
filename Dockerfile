FROM maven:3.9.8-eclipse-temurin-21 AS builder
WORKDIR /workspace

COPY pom.xml ./

COPY identity-service identity-service
COPY notification-service notification-service
COPY profile-service profile-service
COPY api-gateway api-gateway
RUN mvn -B clean package -DskipTests

FROM eclipse-temurin:21-alpine AS gateway-runtime
WORKDIR /app
COPY --from=builder /workspace/api-gateway/target/*.jar app.jar
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar app.jar"]

FROM eclipse-temurin:21-alpine AS identity-runtime
WORKDIR /app
COPY --from=builder /workspace/identity-service/target/*.jar app.jar
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar app.jar"]

FROM eclipse-temurin:21-alpine AS notification-runtime
WORKDIR /app
COPY --from=builder /workspace/notification-service/target/*.jar app.jar
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar app.jar"]

FROM eclipse-temurin:21-alpine AS profile-runtime
WORKDIR /app
COPY --from=builder /workspace/profile-service/target/*.jar app.jar
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar app.jar"]