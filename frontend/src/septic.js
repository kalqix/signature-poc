import init, { generate_keypair, sign_order } from './wasm-pkg/wasm_signer.js'

let wasmReadyPromise = null

export function initWasm() {
  if (!wasmReadyPromise) {
    wasmReadyPromise = init().then(() => true)
  }
  return wasmReadyPromise
}

/// Generate a fresh septic Schnorr key pair (~50ms on WASM).
/// Returns `{ privLimbs: Uint32Array(8), pubX: Uint32Array(7), pubY: Uint32Array(7) }`.
export function generateSepticKeyPair() {
  const raw = generate_keypair()
  return {
    privLimbs: new Uint32Array(raw.priv_limbs),
    pubX: new Uint32Array(raw.pub_x),
    pubY: new Uint32Array(raw.pub_y),
  }
}

/// Sign an order message with a septic Schnorr key.
/// Returns `{ rX, rY, s, challengeE, pubkeyX, pubkeyY }` as Uint32Arrays.
export function signSepticOrder(privLimbs, pubX, pubY, message) {
  const raw = sign_order(
    privLimbs instanceof Uint32Array ? privLimbs : new Uint32Array(privLimbs),
    pubX instanceof Uint32Array ? pubX : new Uint32Array(pubX),
    pubY instanceof Uint32Array ? pubY : new Uint32Array(pubY),
    message,
  )
  return {
    rX: new Uint32Array(raw.r_x),
    rY: new Uint32Array(raw.r_y),
    s: new Uint32Array(raw.s),
    challengeE: new Uint32Array(raw.challenge_e),
    pubkeyX: new Uint32Array(raw.pubkey_x),
    pubkeyY: new Uint32Array(raw.pubkey_y),
  }
}

/// Pack `[Fp7_x, Fp7_y]` (14 u32 limbs, 56 bytes) as a hex string for display.
export function septicPubkeyToHex(pubX, pubY) {
  const bytes = new Uint8Array(56)
  const dv = new DataView(bytes.buffer)
  for (let i = 0; i < 7; i++) {
    dv.setUint32(i * 4, pubX[i], true)
    dv.setUint32(28 + i * 4, pubY[i], true)
  }
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}
