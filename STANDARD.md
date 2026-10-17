# Standard note — CCS (Correctover Conformance Shape)

The reference guard in this repository implements the parameter-risk ideas of
**CCS**, an open 7-dimension runtime-verification shape for AI agents
(Structure, Schema, Latency, Cost, Identity, Integrity, Security). The
parameter-risk portion is documented in an individual Internet-Draft submission.

> **Status notice.** That Internet-Draft is an *individual submission*. It is
> **not an RFC** and does **not** imply IETF endorsement, standardization,
> adoption, or any certification by the IETF or any working group.

- Internet-Draft concept record (always resolves to the latest revision),
  Zenodo DOI: `10.5281/zenodo.21783722`
- parameter-risk draft (-01), Zenodo DOI: `10.5281/zenodo.23365412`

This repository is a **reference implementation of the verification logic**,
not the production enforcement engine. In particular:

- open here: schema profiling → policy evaluation → value-rule scan with
  read-only evidence views (the Security-dimension parameter-risk part);
- proprietary and excluded: the independent cross-process fail-closed
  verifier, the pinned Ed25519 trust root, the signed adjudication-receipt
  kernel (Identity/Integrity enforcement), and the fail-closed IPC transport.

Conformance to the open shape is therefore separable from using the
proprietary enforcement product: a third party may implement the shape from the
published specification and this reference, while the independently verifiable,
signed fail-closed runtime remains Correctover's commercial offering.
