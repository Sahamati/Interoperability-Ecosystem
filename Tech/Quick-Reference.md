# Quick Reference

Paths are relative to the `Tech` folder.

## Generic PRD

PRDs for any AA, FIU or FIP building interoperability.

| Item | Path |
|---|---|
| AA PRD: Interoperability for AAs | [PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/AA/interop-aa-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/AA/interop-aa-prd.md) |
| FIU PRD: Interoperability for FIUs | [PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/FIU/interop-fiu-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/FIU/interop-fiu-prd.md) |
| FIP PRD: Interoperability for FIPs | [PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/FIP/interop-fip-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/General-PRDs/FIP/interop-fip-prd.md) |

## Specifications

Encryption, hashing, Central Registry, Token Service and AIG specifications.

| Item | Path |
|---|---|
| Encryption in Interoperability (guide) | [specifications/Encryption/interop-Encryption in Interoperability.pdf](<specifications/Encryption/interop-Encryption in Interoperability.pdf>) |
| Encryption sample: Go | [specifications/Encryption/samples/go/gosample](specifications/Encryption/samples/go/gosample) |
| Encryption sample: Java | [specifications/Encryption/samples/java/javasample](specifications/Encryption/samples/java/javasample) |
| Hashing Guide for User Discovery (`vuaHash`, `mobileHash`) | [specifications/user-and-vua-hashing/interop-user-discovery-hashing-guide.md](specifications/user-and-vua-hashing/interop-user-discovery-hashing-guide.md) |
| Central Registry: entityinfo API | [specifications/CR-and-TokenService-APIs/interop-central-registry-entityinfo-api.md](specifications/CR-and-TokenService-APIs/interop-central-registry-entityinfo-api.md) |
| CR & Token Service APIs v1.0 (document) | [specifications/CR-and-TokenService-APIs/interop-Sahamati-Interop-CR-Token-APIs_v1.0.pdf](specifications/CR-and-TokenService-APIs/interop-Sahamati-Interop-CR-Token-APIs_v1.0.pdf) |
| CR & Token Service APIs v1.0 (OpenAPI) | [specifications/CR-and-TokenService-APIs/interop-Sahamati-Interop-CR-Token-APIs_v1.0.yaml](specifications/CR-and-TokenService-APIs/interop-Sahamati-Interop-CR-Token-APIs_v1.0.yaml) |
| AIG APIs v1.2 (document) | [specifications/AIG/interop-Sahamati-AIG-APIs_v1.2.pdf](specifications/AIG/interop-Sahamati-AIG-APIs_v1.2.pdf) |
| AIG APIs v1.2 (OpenAPI) | [specifications/AIG/interop-Sahamati-AIG-APIs_v1.2.yaml](specifications/AIG/interop-Sahamati-AIG-APIs_v1.2.yaml) |

## Proposed ReBIT specifications

Proposed specifications, not yet approved by ReBIT.

| Item | Path |
|---|---|
| AA Interop 1.0.0 | [specifications/proposed-unapproved-rebit-api-specifications/AA_Interop_1_0_0_1.yaml](specifications/proposed-unapproved-rebit-api-specifications/AA_Interop_1_0_0_1.yaml) |
| FIU Interop 1.0.0 | [specifications/proposed-unapproved-rebit-api-specifications/FIU_Interop_1_0_0_1.yaml](specifications/proposed-unapproved-rebit-api-specifications/FIU_Interop_1_0_0_1.yaml) |
| FIP Interop 1.0.0 | [specifications/proposed-unapproved-rebit-api-specifications/FIP_Interop_1_0_0_1.yaml](specifications/proposed-unapproved-rebit-api-specifications/FIP_Interop_1_0_0_1.yaml) |
| FIP 2.2.0 | [specifications/proposed-unapproved-rebit-api-specifications/FIP_2_2_0.yaml](specifications/proposed-unapproved-rebit-api-specifications/FIP_2_2_0.yaml) |

## IOP Gw software and components

### PRD for Iop-Gw and Integration guide

The Sahamati IOP Gateway, and how an aa-core, fiu-core or fip-core connects to it.

| Item | Path |
|---|---|
| IOP Gateway: Product Requirements | [PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/iop-gw/interop-ecosystem_iop-gateway-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/iop-gw/interop-ecosystem_iop-gateway-prd.md) |
| IOP Gateway: Integration Guide for the aa-core | [PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/AA/interop-ecosystem_aa-core-interface-to-iop-gw-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/AA/interop-ecosystem_aa-core-interface-to-iop-gw-prd.md) |
| IOP Gateway: Integration Guide for the fiu-core | [PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/FIU/interop-ecosystem_fiu-core-interface-to-iop-gw-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/FIU/interop-ecosystem_fiu-core-interface-to-iop-gw-prd.md) |
| IOP Gateway: Integration Guide for the fip-core | [PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/FIP/interop-ecosystem_fip-core-interface-to-iop-gw-prd.md](PRDs/ecosystem/IOP-APIs-Implementation/Sahamati-Reference-Implementation/FIP/interop-ecosystem_fip-core-interface-to-iop-gw-prd.md) |

### Software

Deploying and testing the IOP Gateway.

| Item | Path |
|---|---|
| Set-up guide | [software/iop-gw-components/SETUP.md](software/iop-gw-components/SETUP.md) |
| Core ↔ IOP Gateway APIs (OpenAPI) | [software/iop-gw-components/docs/api](software/iop-gw-components/docs/api) |
| Helm chart | [software/iop-gw-components/helm/iop-gw](software/iop-gw-components/helm/iop-gw) |
| Helm production values | [software/iop-gw-components/helm/iop-gw/values-production.yaml](software/iop-gw-components/helm/iop-gw/values-production.yaml) |
