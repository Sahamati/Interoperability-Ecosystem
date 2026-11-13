# IOP Gateway

The IOP Gateway lets an AA, FIU or FIP exchange messages with participants it is not directly
connected to, through other AAs. It runs next to the participant's own system (its core) and does
the interoperability work: signatures, end-to-end encryption, routing through a hop AA, and
retries. One image serves all three participant types; `mode` in the configuration selects one.

**To install and configure it, see [../SETUP.md](../SETUP.md).**

## Build

The container image builds from source; only Docker is needed:

```bash
docker build -t iop-gw:0.0.0.0 .                          # tests skipped
docker build --build-arg MVN_ARGS= -t iop-gw:0.0.0.0 .    # with the tests
```

Without Docker (JDK 21 and Maven 3.6 or later): `mvn package` runs the tests and builds
`target/iop-gw-0.0.0.0.jar`; run it with `java -jar target/iop-gw-0.0.0.0.jar <config.yaml>`.
