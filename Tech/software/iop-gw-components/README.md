# IOP Gateway components

The IOP Gateway lets an Account Aggregator (AA), Financial Information User (FIU) or Financial
Information Provider (FIP) exchange messages with participants it is not directly connected to,
through other AAs. Each participant runs its own gateway next to its existing system (its core);
the gateway signs, encrypts and routes the messages, and talks to the Sahamati token service,
Central Registry and AA Interoperability Graph (AIG).

Version: **0.0.0.0**.

## What is in this folder

| Path | What it is |
|---|---|
| [SETUP.md](SETUP.md) | **The main guide**: how the gateway works, what to prepare, installation, every configuration setting, what your core must do, keys and rotation, security, checks and troubleshooting. |
| [MOCK_SETUP.md](MOCK_SETUP.md) | How to try the gateway without the Sahamati services, using `iop-gw-mocks`. |
| `iop-gw/` | The IOP Gateway: source and Dockerfile. |
| `iop-gw-mocks/` | A local stand-in for the Sahamati token service, Central Registry and AIG, for testing only: source and Dockerfile. |
| `helm/iop-gw/` | Helm chart for the gateway. By default it uses the mocks; `values-production.yaml` switches it to the Sahamati services. |
| `helm/iop-gw-mocks/` | Helm chart for the mocks. |
| `helm/examples/mock-setup/` | Installs the mocks and four gateways, wired together, on a Kubernetes cluster. |
| `examples/local/` | The same idea with Docker Compose, on one machine. |

## Where to start

1. **Understand the gateway.** Read [SETUP.md](SETUP.md), sections 1 to 3: how messages flow, what
   you need before you start, and which mode (AA, FIU or FIP) you run.

2. **Build the images.** Only Docker is needed:

   ```bash
   cd iop-gw       && docker build -t iop-gw:0.0.0.0 .
   cd ../iop-gw-mocks && docker build -t iop-gw-mocks:0.0.0.0 .
   ```

   For Kubernetes, push them to a registry your cluster can pull from.

3. **Try it with the mocks.** No credentials or connection to Sahamati are needed:

   - on one machine with Docker: [MOCK_SETUP.md](MOCK_SETUP.md), section 2 (`examples/local`);
   - on a Kubernetes cluster: [MOCK_SETUP.md](MOCK_SETUP.md), section 8
     (`helm/examples/mock-setup`). You can connect your own core to it there (section 8.2), to try
     your core changes before going further.

4. **Prepare for the Sahamati services.** Your entity's Central Registry entry (with your public
   signing and encryption keys, your gateway's address and the interop-ready flag) and your
   token-service credentials; your key pairs, the internal API certificate and token; and the
   changes to your core ([SETUP.md](SETUP.md), sections 2, 6 and 7).

5. **Install.** On Kubernetes with the Helm chart, using `values-production.yaml` and a small
   values file of your own ([SETUP.md](SETUP.md), section 4.1); or with Docker or Java
   (sections 4.2 and 4.3). Then check it works ([SETUP.md](SETUP.md), section 9).

## Current status

- **IopToken.** The gateway sends an IopToken, obtained from the token service, on every call to
  another gateway. The Sahamati token service does not issue IopTokens yet. Until it does, the
  gateway cannot complete calls to other gateways on the Sahamati services. Everything can be
  tried end to end with the mocks, which do issue them.
- **Images** are built from this folder (step 2); there is no published image yet.
- **Checking that a received api-key is an IopToken** (rather than an access token) is not yet
  specified, and so not yet enforced ([SETUP.md](SETUP.md), section 12).

## Requirements

| To | You need |
|---|---|
| Build the images | Docker |
| Run on Kubernetes | Kubernetes, Helm 3, `kubectl` |
| Run the Kubernetes mock setup | Also `openssl`, and `keytool` (from a JDK or JRE) or Docker |
| Run the Docker Compose example | Docker with Compose |
| Build or run without Docker | JDK 21 and Maven 3.6 or later |
