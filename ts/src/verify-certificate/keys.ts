// Normalize caller-supplied witness public key input (raw 32-byte Ed25519
// public key OR base64 string encoding those 32 bytes) into a Uint8Array.
// Rejects PEM SPKI, hex, and other formats — the SDK's contract per the
// v1 arc doc is raw-bytes-or-base64 only.
export function normalizeEd25519PublicKey(input: Uint8Array | string): Uint8Array {
  let bytes: Uint8Array;
  if (input instanceof Uint8Array) {
    bytes = input;
  } else if (typeof input === 'string') {
    bytes = new Uint8Array(Buffer.from(input, 'base64'));
  } else {
    throw new TypeError('Ed25519 public key must be Uint8Array or base64 string');
  }
  if (bytes.length !== 32) {
    throw new TypeError(`Ed25519 public key must be 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}
