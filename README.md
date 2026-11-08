# Correctover Guard - Reference Implementation

Complete MCP runtime behavior protection system that integrates CCS verification, runtime guarding, and signed receipts.

## Features

- **Real-time Monitoring**: Intercept and analyze all MCP protocol messages
- **Policy Enforcement**: Configurable security policies with multiple severity levels
- **Behavior Evidence**: Cryptographically signed attestation receipts
- **Risk Assessment**: Dynamic risk level calculation based on violations
- **Ed25519 Signatures**: All receipts are cryptographically signed and verifiable

## Installation

```bash
npm install correctover-guard-reference
```

## Quick Start

```typescript
import { createGuard } from 'correctover-guard-reference';

// Create guard with default policies
const guard = createGuard({ mode: 'monitor' });

// Start monitoring a session
guard.startSession('session-1', 'mcp-server-id');

// Intercept requests
const result = guard.interceptRequest('session-1', {
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/call',
  params: { name: 'my-tool' }
});

if (!result.allowed) {
  console.log('Blocked:', result.violations);
}

// End session and get attestation receipt
const receipt = guard.endSession('session-1');
console.log('Verdict:', receipt.verdict); // PASS, FAIL, or CONDITIONAL
```

## Modes

- **monitor**: Log all activity, never block (default)
- **enforce**: Block requests that violate policies
- **audit**: Generate detailed compliance reports

## Default Policies

1. **No Data Exfiltration**: Prevent unauthorized data transfer
2. **No Permission Escalation**: Block permission changes
3. **Tool Allowlist**: Only allow declared tools

## Receipt Verification

```typescript
const isValid = guard.verifyReceipt(receipt);
console.log('Receipt valid:', isValid);
```

## Architecture

This reference implementation demonstrates the Correctover Guard architecture:

1. **Interceptor Layer**: Transparent proxy for MCP protocol
2. **Policy Engine**: Rule-based evaluation with severity levels
3. **Evidence Collector**: Structured logging of all behavior
4. **Receipt Generator**: SCITT-style signed attestations
5. **Risk Analyzer**: Dynamic risk assessment

## Standards Alignment

- **RFC 9334**: Remote Attestation procedures
- **SCITT**: Supply Chain Integrity for AI agents
- **RFC 8785**: JSON Canonicalization Scheme
- **Ed25519**: Cryptographic signatures

## License

MIT
