# Use a base image with Java and Gradle for the build stage
FROM gradle:8.5.0-jdk21-jammy AS build

# Set the working directory inside the container
WORKDIR /home/gradle/src

# Copy the entire project into the container
COPY . .

# Run the Gradle build to create the executable JAR file
# Using --no-daemon is recommended for CI/CD environments like Docker
RUN gradle build --no-daemon

# Use a valid, official, and lightweight JRE image for the final container.
# "eclipse-temurin" is a widely trusted source for OpenJDK builds.
FROM eclipse-temurin:21-jre-jammy

# Set the working directory
WORKDIR /app

# Copy the built JAR from the 'build' stage into the final image
COPY --from=build /home/gradle/src/build/libs/*.jar /app/app.jar

# Expose the port the service runs on (e.g., 8080 for auth-service)
EXPOSE 8080

# The command to run the application when the container starts
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

