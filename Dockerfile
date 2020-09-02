FROM adoptopenjdk/openjdk9:jdk-9.0.4.11-alpine
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} test-service-jwt-1.31-SNAPSHOT.jar
ENTRYPOINT ["java","-jar","/test-service-jwt-1.31-SNAPSHOT.jar"]