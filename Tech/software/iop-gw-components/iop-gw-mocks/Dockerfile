# iop-gw-mocks container image: a local token service, Central Registry and AIG
# for trying the IOP Gateway without connections. Testing only.
#
# Builds from source; nothing but Docker is needed (from
# iop-gw-components/iop-gw-mocks):
#   docker build -t iop-gw-mocks:0.0.0.0 .
#
# Run: mount mocks.yaml (and the public keys and credentials files it names)
# read-only, and a writable directory for its output (outDir: the TLS
# certificate, truststore, issuer public key and JWKS it generates on start).
# Stage 1: build the jar. MVN_ARGS="" also runs the tests.
FROM maven:3.9.9-eclipse-temurin-21 AS build
ARG MVN_ARGS=-DskipTests
WORKDIR /src
COPY pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -q -B dependency:go-offline
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -q -B package ${MVN_ARGS} \
 && cp target/iop-gw-mocks-*.jar /iop-gw-mocks.jar

# Stage 2: the runtime image.
FROM eclipse-temurin:21.0.13_9-jre-noble

RUN groupadd --system --gid 10002 mocks \
 && useradd --system --uid 10002 --gid mocks --home-dir /opt/iop-gw-mocks --no-create-home --shell /usr/sbin/nologin mocks \
 && mkdir -p /opt/iop-gw-mocks /etc/iop-gw-mocks /var/lib/iop-gw-mocks/out \
 && chown mocks:mocks /var/lib/iop-gw-mocks/out

COPY --from=build --chown=root:root --chmod=0444 /iop-gw-mocks.jar /opt/iop-gw-mocks/iop-gw-mocks.jar

USER 10002:10002
WORKDIR /opt/iop-gw-mocks
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"
ENTRYPOINT ["java", "-jar", "/opt/iop-gw-mocks/iop-gw-mocks.jar"]
CMD ["/etc/iop-gw-mocks/mocks.yaml"]
