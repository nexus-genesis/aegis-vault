/**
 * aegis-guardrail-ap2 — AP2 Mandate co-signing for Aegis authorization snapshots
 *
 * Positioning (docs/strategy/PRODUCT-POSITIONING-v0.2.md §07): "授权快照 →
 * AP2 Mandate 序列化器（格式仍在迁移，做成可插拔）". This package does NOT
 * implement AP2 and does not own the mandate format. It does three things
 * the strategy needs, all verifiable today:
 *
 *   1. Bind: embed an integrity hash of the signed Aegis authorization
 *      snapshot (from aegis-guardrail-x402 or any producer of the same
 *      snapshot shape) into an AP2-shaped mandate payload. A mandate can
 *      then be PROVEN to be covered by a guardrail decision — or proven
 *      NOT to be (verifiers fail closed on mismatch).
 *   2. Co-sign: the guardrail signer adds a cosignature over
 *      (mandate payload hash, snapshot hash). Dispute evidence = mandate +
 *      snapshot + cosignature, three artifacts that must agree.
 *   3. Adapt: AP2 field names live in ONE serializer module per spec
 *      version ('ap2-v0.2' today). When FIDO ships v1.x, register the new
 *      serializer — binding invariants never change.
 *
 * NOT done here (deliberately): SD-JWT/JWS envelope encoding. AP2 uses
 * SD-JWTs; the JOSE layer is integrator-owned (spec + lib choice still
 * moving). We emit the payload + signature material; wrap it at the edge.
 */
import { keccak256, toUtf8Bytes } from 'ethers';

export const AEGIS_AP2_BINDING_VERSION = 1;

/** Only guardrail ALLOW snapshots may be bound into mandates. Fail-closed. */
const ALLOWED_SNAPSHOT_DECISION = 'allow';

function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalize).join(',')}]`;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
}

/**
 * Integrity hash of an authorization snapshot: canonical form without the
 * `signature` field (mirroring how the producer signed it), keccak-256.
 * Recomputable by any verifier holding the snapshot.
 */
export function snapshotHash(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') {
    throw new TypeError('snapshot is required');
  }
  const { signature, ...rest } = snapshot;
  return keccak256(toUtf8Bytes(canonicalize(rest)));
}

/** Deterministic hash of a mandate payload excluding the aegis.cosignature. */
export function mandatePayloadHash(mandate) {
  if (!mandate || typeof mandate !== 'object') {
    throw new TypeError('mandate is required');
  }
  const { aegis, ...rest } = mandate;
  const { cosignature, ...aegisRest } = aegis ?? {};
  return keccak256(toUtf8Bytes(canonicalize({ ...rest, aegis: aegisRest })));
}

// ─── Pluggable per-spec-version serializers ──────────────────────────────
//
// The only module that knows AP2 field names. Provisional per AP2 v0.2
// (Apr 2026, FIDO) + the UCP AP2-Mandates extension (2026-01-11); when the
// spec finalizes a v1.x shape, register it — nothing else changes.

const SERIALIZERS = {
  'ap2-v0.2': {
    checkout: (snapshot, ctx) => ({
      checkout: {
        id: ctx.checkoutId ?? snapshot.requestId ?? null,
        contents: (ctx.contents ?? []).map((c) => ({
          id: c.id ?? null,
          label: c.label ?? null,
          price: String(c.price)
        })),
        total: String(ctx.total ?? snapshot.amount)
      },
      merchant_origin: ctx.merchantOrigin ?? null,
      aegis: aegisBinding(snapshot)
    }),
    payment: (snapshot, ctx) => ({
      payment_mandate: {
        payment_mandate_id: ctx.paymentMandateId ?? snapshot.requestId ?? null,
        payment_details: {
          total: String(snapshot.amount),
          currency: snapshot.asset,
          recipient: snapshot.payTo,
          chain: snapshot.chain ?? null
        },
        payment_method: ctx.paymentMethod ?? null,
        merchant_origin: ctx.merchantOrigin ?? null,
        fraud_signals: ctx.fraudSignals ?? null
      },
      aegis: aegisBinding(snapshot)
    })
  }
};

function aegisBinding(snapshot) {
  return {
    binding_version: AEGIS_AP2_BINDING_VERSION,
    guardrail: 'aegis-vault',
    decision: snapshot.decision,
    tier: snapshot.tier ?? null,
    snapshot_hash: snapshotHash(snapshot),
    snapshot_expires_at: snapshot.expiresAt ?? null
  };
}

export function registerAp2Serializer(version, impl) {
  if (!version || typeof version !== 'string') throw new TypeError('version is required');
  if (!impl || typeof impl.checkout !== 'function' || typeof impl.payment !== 'function') {
    throw new TypeError('serializer must provide checkout(snapshot, ctx) and payment(snapshot, ctx)');
  }
  SERIALIZERS[version] = impl;
}

// ─── Builder ─────────────────────────────────────────────────────────────

/**
 * @param {object} options
 * @param {Function} options.sign `async (preimage) => signature` — same
 *   signer-agnostic contract as aegis-guardrail-x402 (session key, PQC op
 *   key, remote signer…).
 * @param {Function} [options.verify] `async (preimage, signature) => boolean`
 *   needed only for verifyCosignature().
 * @param {string} [options.specVersion='ap2-v0.2'] registered serializer key
 * @returns {{ toCheckoutMandate, toPaymentMandate, verifyCosignature }}
 */
export function createAp2MandateBuilder({ sign, verify, specVersion = 'ap2-v0.2' } = {}) {
  if (typeof sign !== 'function') {
    throw new TypeError('sign(preimage) is required — co-signing without a signer is theater');
  }
  const serializer = SERIALIZERS[specVersion];
  if (!serializer) {
    throw new TypeError(`unknown specVersion "${specVersion}" — registered: ${Object.keys(SERIALIZERS).join(', ')}`);
  }

  function assertBindAllowed(snapshot) {
    if (!snapshot || typeof snapshot !== 'object') {
      throw new TypeError('snapshot is required');
    }
    if (snapshot.decision !== ALLOWED_SNAPSHOT_DECISION) {
      // A HOLD / APPROVAL_REQUIRED / DENY snapshot must never leak into a
      // payable mandate — that would convert a guardrail into a rubber stamp.
      throw new Error(`snapshot decision "${snapshot.decision}" is not payable (fail-closed)`);
    }
    if (typeof snapshot.signature !== 'string' || !snapshot.signature) {
      throw new Error('snapshot is not signed — an unsigned authorization cannot underwrite a mandate');
    }
    if (snapshot.expiresAt != null && Number(snapshot.expiresAt) <= Date.now()) {
      throw new Error('snapshot expired — mandate binding refused');
    }
  }

  async function bind(kind, snapshot, ctx) {
    assertBindAllowed(snapshot);
    const mandate = serializer[kind](snapshot, ctx ?? {});
    // The binding layer is serializer-independent: custom serializers map
    // AP2 fields, aegis always injects its own binding + cosignature.
    mandate.aegis = mandate.aegis ?? aegisBinding(snapshot);
    mandate.aegis.cosignature = {
      // preimage covers both artifacts so neither can be swapped independently
      payload_hash: mandatePayloadHash(mandate),
      snapshot_hash: aegisBinding(snapshot).snapshot_hash,
      signed_at: Date.now()
    };
    const preimage = canonicalize(mandate.aegis.cosignature);
    mandate.aegis.cosignature.signature = await sign(preimage);
    return mandate;
  }

  /** Serialize an ALLOW snapshot into an AP2-shaped Checkout Mandate payload. */
  async function toCheckoutMandate(snapshot, ctx) {
    return bind('checkout', snapshot, ctx);
  }

  /** Serialize an ALLOW snapshot into an AP2-shaped Payment Mandate payload. */
  async function toPaymentMandate(snapshot, ctx) {
    return bind('payment', snapshot, ctx);
  }

  /**
   * Verify a mandate's Aegis co-signature. Fail-closed: returns {ok:false}
   * on any mismatch between payload hash, snapshot hash and signature.
   *
   * @param {object} mandate the (co-signed) mandate payload
   * @param {object} expected
   * @param {object} expected.snapshot the authorization snapshot the mandate
   *   claims to be bound to
   * @returns {Promise<{ok:boolean, errors:string[]}>}
   */
  async function verifyCosignature(mandate, expected = {}) {
    const errors = [];
    const aegis = mandate?.aegis;
    const cosig = aegis?.cosignature;
    if (!cosig || typeof cosig.signature !== 'string' || !cosig.signature) {
      return { ok: false, errors: ['mandate carries no aegis cosignature'] };
    }
    if (mandatePayloadHash(mandate) !== cosig.payload_hash) {
      errors.push('payload hash mismatch — mandate was modified after co-signing');
    }
    const snap = expected.snapshot;
    if (!snap) {
      errors.push('expected.snapshot missing — refusing to verify against nothing');
    } else {
      if (snapshotHash(snap) !== cosig.snapshot_hash) {
        errors.push('snapshot hash mismatch — mandate is bound to a different authorization');
      }
      if (snap.decision !== ALLOWED_SNAPSHOT_DECISION) {
        errors.push(`snapshot decision "${snap.decision}" is not payable`);
      }
      if (snap.expiresAt != null && Number(snap.expiresAt) <= Date.now()) {
        errors.push('snapshot expired');
      }
    }
    if (typeof verify === 'function' && errors.length === 0) {
      const { signature, ...cosigRest } = cosig;
      const preimage = canonicalize(cosigRest);
      const good = await verify(preimage, signature);
      if (!good) errors.push('cosignature invalid');
    } else if (typeof verify !== 'function') {
      errors.push('builder constructed without verify() — structural checks passed, signature NOT verified');
    }
    return { ok: errors.length === 0, errors };
  }

  return { specVersion, toCheckoutMandate, toPaymentMandate, verifyCosignature };
}
