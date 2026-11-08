/**
 * Correctover Guard - Reference Implementation
 * 
 * Integrates CCS verification, runtime guarding, and signed receipts
 * into a complete MCP security layer.
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import {
  GuardConfig,
  GuardState,
  BehaviorEvidence,
  AttestationReceipt,
  PolicyViolation,
  JsonRpcRequest,
  JsonRpcResponse,
  EvidenceType,
  RiskLevel,
  Verdict,
  GuardEvent,
  SecurityPolicy,
} from './types';

export class CorrectoverGuard extends EventEmitter {
  private config: GuardConfig;
  private states: Map<string, GuardState> = new Map();
  private evidence: Map<string, BehaviorEvidence[]> = new Map();
  private violations: Map<string, PolicyViolation[]> = new Map();
  private privateKey: string;
  private publicKey: string;

  constructor(config: GuardConfig) {
    super();
    this.config = config;
    
    // Generate Ed25519 key pair for signing
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Start monitoring an MCP session
   */
  startSession(sessionId: string, mcpServerId: string): void {
    const state: GuardState = {
      sessionId,
      mcpServerId,
      startTime: new Date().toISOString(),
      evidenceCount: 0,
      violationsCount: 0,
      currentRiskLevel: 'LOW',
      lastActivity: new Date().toISOString(),
    };

    this.states.set(sessionId, state);
    this.evidence.set(sessionId, []);
    this.violations.set(sessionId, []);

    this.emit('session_started', { sessionId, mcpServerId });
  }

  /**
   * Intercept and analyze MCP request
   */
  interceptRequest(sessionId: string, request: JsonRpcRequest): {
    allowed: boolean;
    evidence: BehaviorEvidence;
    violations: PolicyViolation[];
  } {
    const state = this.states.get(sessionId);
    if (!state) {
      throw new Error(`Session ${sessionId} not found`);
    }

    // Capture evidence
    const evidence = this.captureEvidence(sessionId, 'tool_invocation', request.method, {
      params: request.params,
      requestId: request.id,
    });

    // Evaluate policies
    const violations = this.evaluatePolicies(sessionId, evidence);

    // Update state
    state.evidenceCount++;
    state.violationsCount += violations.length;
    state.lastActivity = new Date().toISOString();

    if (violations.length > 0) {
      this.updateRiskLevel(sessionId);
    }

    // Determine if request should be allowed
    const allowed = this.config.mode === 'monitor' || violations.length === 0;

    // Emit events
    violations.forEach(v => this.emit('violation_detected', v));

    return { allowed, evidence, violations };
  }

  /**
   * Intercept and analyze MCP response
   */
  interceptResponse(sessionId: string, response: JsonRpcResponse): BehaviorEvidence {
    const state = this.states.get(sessionId);
    if (!state) {
      throw new Error(`Session ${sessionId} not found`);
    }

    return this.captureEvidence(sessionId, 'tool_invocation', 'response', {
      responseId: response.id,
      hasError: !!response.error,
      resultSize: JSON.stringify(response.result || {}).length,
    });
  }

  /**
   * End session and generate attestation receipt
   */
  endSession(sessionId: string): AttestationReceipt {
    const state = this.states.get(sessionId);
    if (!state) {
      throw new Error(`Session ${sessionId} not found`);
    }

    const sessionEvidence = this.evidence.get(sessionId) || [];
    const sessionViolations = this.violations.get(sessionId) || [];

    // Calculate verdict
    const verdict = this.calculateVerdict(sessionViolations, state.currentRiskLevel);

    // Build evidence summary
    const evidenceSummary = {
      total: sessionEvidence.length,
      byType: this.groupBy(sessionEvidence, 'type') as Record<EvidenceType, number>,
      byRisk: this.groupBy(sessionEvidence, 'riskLevel') as Record<RiskLevel, number>,
    };

    // Generate receipt
    const receipt: AttestationReceipt = {
      receiptId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      guardId: 'correctover-guard-reference-v0.1.0',
      sessionId,
      mcpServerId: state.mcpServerId,
      evidenceSummary,
      violations: sessionViolations,
      verdict,
      signature: '',
      publicKey: this.publicKey,
    };

    // Sign receipt
    receipt.signature = this.signReceipt(receipt);

    // Clean up state
    this.states.delete(sessionId);
    this.evidence.delete(sessionId);
    this.violations.delete(sessionId);

    this.emit('session_ended', { sessionId, receipt });

    return receipt;
  }

  /**
   * Verify an attestation receipt
   */
  verifyReceipt(receipt: AttestationReceipt): boolean {
    const signature = receipt.signature;
    const receiptCopy = { ...receipt, signature: '' };
    const data = JSON.stringify(receiptCopy);

    try {
      const verify = crypto.createVerify('ed25519');
      verify.update(data);
      return verify.verify(this.publicKey, signature, 'base64');
    } catch {
      return false;
    }
  }

  /**
   * Get current session state
   */
  getSessionState(sessionId: string): GuardState | undefined {
    return this.states.get(sessionId);
  }

  /**
   * Get session evidence
   */
  getSessionEvidence(sessionId: string): BehaviorEvidence[] {
    return this.evidence.get(sessionId) || [];
  }

  // Private methods

  private captureEvidence(
    sessionId: string,
    type: EvidenceType,
    action: string,
    details: Record<string, unknown>
  ): BehaviorEvidence {
    const evidence: BehaviorEvidence = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      sessionId,
      type,
      action,
      details,
      riskLevel: 'LOW',
      policyViolations: [],
    };

    const sessionEvidence = this.evidence.get(sessionId) || [];
    sessionEvidence.push(evidence);
    this.evidence.set(sessionId, sessionEvidence);

    this.emit('evidence_captured', evidence);

    return evidence;
  }

  private evaluatePolicies(
    sessionId: string,
    evidence: BehaviorEvidence
  ): PolicyViolation[] {
    const violations: PolicyViolation[] = [];

    for (const policy of this.config.policies) {
      if (!policy.enabled) continue;

      for (let i = 0; i < policy.rules.length; i++) {
        const rule = policy.rules[i];
        const violated = this.checkRule(evidence, rule);

        if (violated) {
          const violation: PolicyViolation = {
            policyId: policy.id,
            ruleIndex: i,
            evidenceId: evidence.id,
            timestamp: new Date().toISOString(),
            description: `${policy.name}: ${rule.type} ${rule.target}`,
            severity: policy.severity,
          };

          violations.push(violation);

          const sessionViolations = this.violations.get(sessionId) || [];
          sessionViolations.push(violation);
          this.violations.set(sessionId, sessionViolations);

          evidence.policyViolations.push(policy.id);
        }
      }
    }

    return violations;
  }

  private checkRule(
    evidence: BehaviorEvidence,
    rule: { type: string; target: string; value?: unknown }
  ): boolean {
    // Simple rule evaluation logic
    switch (rule.type) {
      case 'deny':
        return evidence.action.includes(rule.target);
      case 'require':
        return !evidence.details[rule.target];
      case 'limit':
        const current = (evidence.details[rule.target] as number) || 0;
        const limit = (rule.value as number) || 0;
        return current > limit;
      default:
        return false;
    }
  }

  private updateRiskLevel(sessionId: string): void {
    const state = this.states.get(sessionId);
    const sessionViolations = this.violations.get(sessionId) || [];

    if (!state) return;

    const criticalCount = sessionViolations.filter(v => v.severity === 'CRITICAL').length;
    const highCount = sessionViolations.filter(v => v.severity === 'HIGH').length;

    let newLevel: RiskLevel = 'LOW';
    if (criticalCount > 0 || highCount > 2) {
      newLevel = 'CRITICAL';
    } else if (highCount > 0) {
      newLevel = 'HIGH';
    } else if (sessionViolations.length > 0) {
      newLevel = 'MEDIUM';
    }

    if (newLevel !== state.currentRiskLevel) {
      state.currentRiskLevel = newLevel;
      this.emit('risk_level_changed', { sessionId, newLevel });
    }
  }

  private calculateVerdict(violations: PolicyViolation[], riskLevel: RiskLevel): Verdict {
    const criticalCount = violations.filter(v => v.severity === 'CRITICAL').length;
    const highCount = violations.filter(v => v.severity === 'HIGH').length;

    if (criticalCount > 0 || highCount > 2) {
      return 'FAIL';
    } else if (violations.length > 0 || riskLevel === 'MEDIUM') {
      return 'CONDITIONAL';
    } else {
      return 'PASS';
    }
  }

  private signReceipt(receipt: AttestationReceipt): string {
    const receiptCopy = { ...receipt, signature: '' };
    const data = JSON.stringify(receiptCopy);

    const sign = crypto.createSign('ed25519');
    sign.update(data);
    return sign.sign(this.privateKey, 'base64');
  }

  private groupBy<T, K extends keyof T>(
    items: T[],
    key: K
  ): Record<string, number> {
    return items.reduce((acc, item) => {
      const value = String(item[key]);
      acc[value] = (acc[value] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }
}

// Default policies
export const DEFAULT_POLICIES: SecurityPolicy[] = [
  {
    id: 'no-data-exfiltration',
    name: 'No Data Exfiltration',
    description: 'Prevent unauthorized data transfer to external endpoints',
    rules: [
      { type: 'deny' as const, target: 'network_request' },
      { type: 'limit' as const, target: 'data_size', value: 10 * 1024 * 1024 }, // 10MB
    ],
    severity: 'CRITICAL' as const,
    enabled: true,
  },
  {
    id: 'no-permission-escalation',
    name: 'No Permission Escalation',
    description: 'Prevent MCP servers from escalating beyond declared permissions',
    rules: [
      { type: 'deny' as const, target: 'permission_change' },
    ],
    severity: 'CRITICAL' as const,
    enabled: true,
  },
  {
    id: 'tool-allowlist',
    name: 'Tool Allowlist',
    description: 'Only allow declared tools to be invoked',
    rules: [
      { type: 'require' as const, target: 'tool_declared' },
    ],
    severity: 'HIGH' as const,
    enabled: true,
  },
];

// Factory function
export function createGuard(config?: Partial<GuardConfig>): CorrectoverGuard {
  const fullConfig: GuardConfig = {
    mode: config?.mode || 'monitor',
    policies: config?.policies || DEFAULT_POLICIES,
    logging: config?.logging || {
      level: 'info',
      format: 'json',
      output: 'stdout',
    },
    signing: config?.signing || {
      enabled: true,
      algorithm: 'Ed25519',
    },
    alerts: config?.alerts || {
      enabled: false,
      channels: [],
      threshold: 'HIGH',
    },
  };

  return new CorrectoverGuard(fullConfig);
}
