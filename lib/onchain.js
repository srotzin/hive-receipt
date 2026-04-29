// On-chain transaction verification helper
// Best-effort: if RPC unreachable, returns verification_status:"unverified"
import { fetch as undiciFetch } from 'undici';

// Public RPC endpoints
const BASE_RPC   = 'https://mainnet.base.org';
const ETH_RPC    = 'https://eth.llamarpc.com';
const SOL_RPC    = 'https://api.mainnet-beta.solana.com';

async function jsonRpcCall(url, method, params, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await undiciFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: ctrl.signal
    });
    const data = await res.json();
    return { ok: true, result: data.result };
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Verify an EVM tx (Base or Ethereum).
 * Returns {verified, verification_status, verification_attempted, details?}
 */
async function verifyEvm(txHash, rpcUrl, expectedRecipient, expectedAmountAtomic, expectedAsset) {
  const resp = await jsonRpcCall(rpcUrl, 'eth_getTransactionReceipt', [txHash]);
  if (!resp.ok || !resp.result) {
    return {
      verified: false,
      verification_attempted: true,
      verification_status: 'unverified',
      details: { error: resp.error || 'null receipt — tx pending or not found' }
    };
  }
  const receipt = resp.result;
  const success = receipt.status === '0x1';
  return {
    verified: success,
    verification_attempted: true,
    verification_status: success ? 'verified' : 'failed',
    details: {
      block_number: parseInt(receipt.blockNumber, 16),
      tx_hash: receipt.transactionHash,
      from: receipt.from,
      to: receipt.to,
      status: receipt.status
    }
  };
}

/**
 * Verify a Solana tx.
 */
async function verifySolana(txSignature) {
  const resp = await jsonRpcCall(SOL_RPC, 'getTransaction', [txSignature, { encoding: 'json', commitment: 'confirmed' }]);
  if (!resp.ok || !resp.result) {
    return {
      verified: false,
      verification_attempted: true,
      verification_status: 'unverified',
      details: { error: resp.error || 'tx not found or not confirmed' }
    };
  }
  const tx = resp.result;
  const success = tx?.meta?.err === null;
  return {
    verified: success,
    verification_attempted: true,
    verification_status: success ? 'verified' : 'failed',
    details: {
      slot: tx.slot,
      block_time: tx.blockTime
    }
  };
}

/**
 * Main verification dispatcher.
 */
export async function verifyOnChain({ tx_hash, network, expected_recipient, expected_amount_atomic, expected_asset }) {
  if (!tx_hash) {
    return { verified: false, verification_attempted: false, verification_status: 'no_tx_hash' };
  }
  try {
    if (network === 'base') {
      return await verifyEvm(tx_hash, BASE_RPC, expected_recipient, expected_amount_atomic, expected_asset);
    } else if (network === 'ethereum') {
      return await verifyEvm(tx_hash, ETH_RPC, expected_recipient, expected_amount_atomic, expected_asset);
    } else if (network === 'solana') {
      return await verifySolana(tx_hash);
    } else {
      return { verified: false, verification_attempted: false, verification_status: 'unsupported_network' };
    }
  } catch (e) {
    return {
      verified: false,
      verification_attempted: true,
      verification_status: 'unverified',
      details: { error: e.message }
    };
  }
}
