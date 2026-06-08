# Expects target/spring-demo-0.1.0.jar to be prebuilt (scripts/mvn package).
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY target/spring-demo-0.1.0.jar /app/app.jar
EXPOSE 5002
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
