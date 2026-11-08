import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createGuard, CorrectoverGuard } from '../src/guard';
import { JsonRpcRequest } from '../src/types';

describe('CorrectoverGuard', () => {
  let guard: CorrectoverGuard;

  it('should create guard with default config', () => {
    guard = createGuard();
    assert.ok(guard instanceof CorrectoverGuard);
  });

  it('should start and end session', () => {
    guard = createGuard({ mode: 'monitor' });
    const sessionId = 'test-session-1';
    const mcpServerId = 'test-server';

    guard.startSession(sessionId, mcpServerId);
    const state = guard.getSessionState(sessionId);
    
    assert.ok(state);
    assert.strictEqual(state.sessionId, sessionId);
    assert.strictEqual(state.mcpServerId, mcpServerId);
    assert.strictEqual(state.currentRiskLevel, 'LOW');

    const receipt = guard.endSession(sessionId);
    assert.ok(receipt.receiptId);
    assert.strictEqual(receipt.verdict, 'PASS');
    assert.ok(receipt.signature);
  });

  it('should intercept requests and capture evidence', () => {
    guard = createGuard({ mode: 'monitor' });
    const sessionId = 'test-session-2';
    
    guard.startSession(sessionId, 'server-2');

    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'test-tool', arguments: {} },
    };

    const result = guard.interceptRequest(sessionId, request);
    assert.ok(result.evidence);
    assert.strictEqual(result.evidence.type, 'tool_invocation');

    const evidence = guard.getSessionEvidence(sessionId);
    assert.strictEqual(evidence.length, 1);

    guard.endSession(sessionId);
  });

  it('should detect policy violations in enforce mode', () => {
    guard = createGuard({ mode: 'enforce' });
    const sessionId = 'test-session-3';
    
    guard.startSession(sessionId, 'server-3');

    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      id: 2,
      method: 'network_request',
      params: { url: 'https://external.com' },
    };

    const result = guard.interceptRequest(sessionId, request);
    assert.strictEqual(result.allowed, false);
    assert.ok(result.violations.length > 0);

    const receipt = guard.endSession(sessionId);
    assert.strictEqual(receipt.verdict, 'FAIL');

    guard.endSession(sessionId);
  });

  it('should sign and verify receipts', () => {
    guard = createGuard({ mode: 'monitor' });
    const sessionId = 'test-session-4';
    
    guard.startSession(sessionId, 'server-4');
    const receipt = guard.endSession(sessionId);

    const isValid = guard.verifyReceipt(receipt);
    assert.strictEqual(isValid, true);
  });
});
