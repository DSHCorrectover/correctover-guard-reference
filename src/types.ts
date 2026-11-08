/**
 * Core type definitions for Correctover Guard
 */

// MCP Protocol types
export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface JsonRpcNotification {
  jsonrpc: '2.0';
  method: string;
  params?: Record<string, unknown>;
}

// Guard configuration
export interface GuardConfig {
  mode: 'monitor' | 'enforce' | 'audit';
  policies: SecurityPolicy[];
  logging: LoggingConfig;
  signing: SigningConfig;
  alerts: AlertConfig;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  description: string;
  rules: PolicyRule[];
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  enabled: boolean;
}

export interface PolicyRule {
  type: 'allow' | 'deny' | 'require' | 'limit';
  target: string;
  condition?: string;
  value?: unknown;
}

export interface LoggingConfig {
  level: 'debug' | 'info' | 'warn' | 'error';
  format: 'json' | 'text';
  output: 'stdout' | 'file' | 'remote';
  filePath?: string;
  remoteUrl?: string;
}

export interface SigningConfig {
  enabled: boolean;
  algorithm: 'Ed25519' | 'ES256';
  privateKeyPath?: string;
  publicKeyPath?: string;
  timestampAuthority?: string;
}

export interface AlertConfig {
  enabled: boolean;
  channels: AlertChannel[];
  threshold: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface AlertChannel {
  type: 'webhook' | 'email' | 'slack' | 'pagerduty';
  config: Record<string, string>;
}

// Behavior evidence
export interface BehaviorEvidence {
  id: string;
  timestamp: string;
  sessionId: string;
  type: EvidenceType;
  action: string;
  details: Record<string, unknown>;
  riskLevel: RiskLevel;
  policyViolations: string[];
}

export type EvidenceType = 
  | 'tool_invocation'
  | 'resource_access'
  | 'network_request'
  | 'file_operation'
  | 'permission_change'
  | 'data_exfiltration_attempt'
  | 'anomaly_detected';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// Guard state
export interface GuardState {
  sessionId: string;
  startTime: string;
  mcpServerId: string;
  evidenceCount: number;
  violationsCount: number;
  currentRiskLevel: RiskLevel;
  lastActivity: string;
}

// Attestation receipt
export interface AttestationReceipt {
  receiptId: string;
  timestamp: string;
  guardId: string;
  sessionId: string;
  mcpServerId: string;
  evidenceSummary: {
    total: number;
    byType: Record<EvidenceType, number>;
    byRisk: Record<RiskLevel, number>;
  };
  violations: PolicyViolation[];
  verdict: Verdict;
  signature: string;
  publicKey: string;
}

export interface PolicyViolation {
  policyId: string;
  ruleIndex: number;
  evidenceId: string;
  timestamp: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export type Verdict = 'PASS' | 'FAIL' | 'CONDITIONAL';

// Guard events
export type GuardEvent = 
  | { type: 'session_started'; sessionId: string; mcpServerId: string }
  | { type: 'evidence_captured'; evidence: BehaviorEvidence }
  | { type: 'violation_detected'; violation: PolicyViolation }
  | { type: 'risk_level_changed'; sessionId: string; newLevel: RiskLevel }
  | { type: 'session_ended'; sessionId: string; receipt: AttestationReceipt };
