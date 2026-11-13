# IOP Gateway container image. Builds the gateway from source; nothing but
# Docker is needed (from iop-gw-components/iop-gw):
#   docker build -t iop-gw:0.0.0.0 .
#
# Run: mount the configuration (and the key, certificate and credentials files
# it names) read-only, give the cache a volume, and pass secrets as environment
# variables (the configuration refers to them as ${NAME}):
#   docker run --rm -p 8443:8443 -p 9443:9443 \
#     -v "$PWD/config:/etc/iop-gw:ro" -v iop-gw-cache:/var/lib/iop-gw/cache \
#     -e IOPGW_API_TOKEN=... iop-gw:0.0.0.0
#
# The ports are the ones in the configuration (listenAddr, gwApi.listenAddr,
# gwApi.httpListenAddr). Readiness: GET /healthz on the public listener.

# Stage 1: build the jar (MVN_ARGS="" also runs the tests, a few minutes more),
# and unpack RocksDB's native libraries from it, so the gateway never has to
# extract and run them from /tmp (often a noexec tmpfs in hardened
# deployments, where loading them from there fails).
FROM maven:3.9.9-eclipse-temurin-21 AS build
ARG MVN_ARGS=-DskipTests
WORKDIR /src
COPY pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -q -B dependency:go-offline
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -q -B package ${MVN_ARGS} \
 && cp target/iop-gw-*.jar /iop-gw.jar \
 && mkdir /native && cd /native \
 && jar xf /iop-gw.jar librocksdbjni-linux64.so librocksdbjni-linux-aarch64.so \
 && chmod 0444 /native/*.so

# Stage 2: the runtime image.
FROM eclipse-temurin:21.0.13_9-jre-noble

# A dedicated non-root user; the cache directory is the only place it writes
# besides /tmp (the embedded HTTP server's work directory; nothing is executed
# from /tmp, so it may be a noexec tmpfs).
RUN groupadd --system --gid 10001 iopgw \
 && useradd --system --uid 10001 --gid iopgw --home-dir /opt/iop-gw --no-create-home --shell /usr/sbin/nologin iopgw \
 && mkdir -p /opt/iop-gw /etc/iop-gw /var/lib/iop-gw/cache \
 && chown iopgw:iopgw /var/lib/iop-gw /var/lib/iop-gw/cache \
 && chmod 0700 /var/lib/iop-gw/cache

COPY --from=build --chown=root:root --chmod=0444 /iop-gw.jar /opt/iop-gw/iop-gw.jar
COPY --from=build --chown=root:root /native/ /opt/iop-gw/native/

USER 10001:10001
WORKDIR /opt/iop-gw

# Memory follows the container limit; an out-of-memory error stops the process
# (the orchestrator restarts it) instead of leaving it half-working. No heap
# dumps: they would contain the private keys held in memory.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError -XX:-HeapDumpOnOutOfMemoryError"

VOLUME ["/var/lib/iop-gw/cache"]
# java.library.path: RocksDB loads its native library from the image, not /tmp.
ENTRYPOINT ["java", "-Djava.library.path=/opt/iop-gw/native", "-jar", "/opt/iop-gw/iop-gw.jar"]
CMD ["/etc/iop-gw/config.yaml"]
