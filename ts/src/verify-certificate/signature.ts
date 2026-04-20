import { verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { normalizeEd25519PublicKey } from './keys.js';

// SPKI DER prefix for raw Ed25519 SubjectPublicKeyInfo. Decoded:
//   30 2a                SEQUENCE (42 bytes content = 7 for AlgId + 35 for BITSTRING)
//   30 05                  SEQUENCE (5 bytes content — AlgorithmIdentifier)
//   06 03 2b 65 70           OID 1.3.101.112 (id-Ed25519)
//   03 21 00               BIT STRING (33 bytes content, unused-bits=0) + 32 key bytes
//
// Building the SPKI wrapper ourselves keeps us compatible with Node 18.17+
// without requiring the newer `format: 'raw', type: 'ed25519'` option.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// Ed25519 verify. Accepts raw 32-byte pubkey (Uint8Array) or base64 string.
// Node's crypto.verify with 'ed25519' mode requires a KeyObject; we build
// one from the SPKI-wrapped raw key via createPublicKey. Returns a plain
// boolean — the orchestrator layer is responsible for translating false
// into a TheVeilCertificateError.
export function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array | string,
): boolean {
  const raw = normalizeEd25519PublicKey(publicKey);
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]);
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return cryptoVerify(null, Buffer.from(message), key, Buffer.from(signature));
}
