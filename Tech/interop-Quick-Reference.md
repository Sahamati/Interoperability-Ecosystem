# Quick Reference

Paths are relative to the `Tech` folder.

## Generic PRD

PRDs for any AA, FIU or FIP building interoperability.

| Item | Path |
|---|---|
| AA PRD: Interoperability for AAs | [PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/AA/aa-interoperability-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/AA/aa-interoperability-prd.md) |
| FIU PRD: Interoperability for FIUs | [PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/FIU/fiu-interoperability-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/FIU/fiu-interoperability-prd.md) |
| FIP PRD: Interoperability for FIPs | [PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/FIP/fip-interoperability-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/FIP/fip-interoperability-prd.md) |

## PRD for Iop-Gw and Integration guide

The Sahamati IOP Gateway, and how an aa-core, fiu-core or fip-core connects to it.

| Item | Path |
|---|---|
| IOP Gateway: Product Requirements | [PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/iop-gw/ecosystem_iop-gateway-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/iop-gw/ecosystem_iop-gateway-prd.md) |
| IOP Gateway: Integration Guide for the aa-core | [PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/AA/ecosystem_aa-core-interface-to-iop-gw-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/AA/ecosystem_aa-core-interface-to-iop-gw-prd.md) |
| IOP Gateway: Integration Guide for the fiu-core | [PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/FIU/ecosystem_fiu-core-interface-to-iop-gw-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/FIU/ecosystem_fiu-core-interface-to-iop-gw-prd.md) |
| IOP Gateway: Integration Guide for the fip-core | [PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/FIP/ecosystem_fip-core-interface-to-iop-gw-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/FIP/ecosystem_fip-core-interface-to-iop-gw-prd.md) |

## Specifications

Encryption, hashing, Central Registry and AIG specifications.

| Item | Path |
|---|---|
| Encryption in Interoperability (guide) | [specifications/Encryption/Encryption in Interoperability.pdf](<specifications/Encryption/Encryption in Interoperability.pdf>) |
| Encryption sample: Go | [specifications/Encryption/samples/go/gosample](specifications/Encryption/samples/go/gosample) |
| Encryption sample: Java | [specifications/Encryption/samples/java/javasample](specifications/Encryption/samples/java/javasample) |
| Hashing Guide for User Discovery (`vuaHash`, `mobileHash`) | [specifications/user-and-vua-hashing/user-discovery-hashing-guide.md](specifications/user-and-vua-hashing/user-discovery-hashing-guide.md) |
| Central Registry: entityinfo API | [specifications/CR-API/central-registry-entityinfo-api.md](specifications/CR-API/central-registry-entityinfo-api.md) |
| AIG APIs (document) | [specifications/AIG/Sahamati-AIG-APIs-v1.0.pdf](specifications/AIG/Sahamati-AIG-APIs-v1.0.pdf) |
| AIG APIs (OpenAPI) | [specifications/AIG/sahamati-aig-api.yaml](specifications/AIG/sahamati-aig-api.yaml) |

## Proposed ReBIT specifications

Proposed specifications, not yet approved by ReBIT.

| Item | Path |
|---|---|
| AA Interop 1.0.0 | [specifications/proposed-unapproved-rebit-api-specifications/AA_Interop_1_0_0-Proposed-1.yaml](specifications/proposed-unapproved-rebit-api-specifications/AA_Interop_1_0_0-Proposed-1.yaml) |
| FIU Interop 1.0.0 | [specifications/proposed-unapproved-rebit-api-specifications/FIU_Interop_1_0_0-Proposed-1.yaml](specifications/proposed-unapproved-rebit-api-specifications/FIU_Interop_1_0_0-Proposed-1.yaml) |
| FIP Interop 1.0.0 | [specifications/proposed-unapproved-rebit-api-specifications/FIP_Interop_1_0_0-Proposed-1.yaml](specifications/proposed-unapproved-rebit-api-specifications/FIP_Interop_1_0_0-Proposed-1.yaml) |
| FIP 2.2.0 | [specifications/proposed-unapproved-rebit-api-specifications/FIP_2_2_0-Proposed-1.yaml](specifications/proposed-unapproved-rebit-api-specifications/FIP_2_2_0-Proposed-1.yaml) |

## IOP Gw software

Deploying and testing the IOP Gateway.

| Item | Path |
|---|---|
| Set-up guide | [software/iop-gw-components/SETUP.md](software/iop-gw-components/SETUP.md) |
| Helm chart | [software/iop-gw-components/helm/iop-gw](software/iop-gw-components/helm/iop-gw) |
| Helm production values | [software/iop-gw-components/helm/iop-gw/values-production.yaml](software/iop-gw-components/helm/iop-gw/values-production.yaml) |
| Helm chart test (kind) | [software/iop-gw-components/helm/test/kind-test.sh](software/iop-gw-components/helm/test/kind-test.sh) |
