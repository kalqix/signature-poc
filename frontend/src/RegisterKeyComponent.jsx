import { useState, useEffect, useCallback } from 'react'
import { useSignMessage } from 'wagmi'
import { loadKeyPair, storeKeyPair, markRegistered } from './db.js'
import { generateSepticKeyPair, septicPubkeyToHex } from './septic.js'

const API = 'http://localhost:3001'
const KEY_INDICES = [0, 1, 2, 3, 4]

const styles = {
  heading: { marginBottom: 12 },
  subheading: { marginTop: 24, marginBottom: 8, fontSize: 14, color: '#aaa' },
  keyRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    padding: '8px 0',
    borderBottom: '1px solid #333',
    fontSize: 13,
    fontFamily: 'monospace',
  },
  keyIndex: { fontWeight: 'bold', minWidth: 50 },
  keyHex: { flex: 1, wordBreak: 'break-all', color: '#6c6', fontSize: 11 },
  empty: { flex: 1, color: '#888' },
  badge: {
    fontSize: 10,
    padding: '2px 6px',
    borderRadius: 4,
    background: '#264',
    color: '#6f6',
  },
  btn: {
    padding: '4px 10px',
    fontFamily: 'monospace',
    fontSize: 12,
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  },
  status: { marginTop: 12, fontSize: 13 },
  error: { color: '#f66' },
  success: { color: '#6c6' },
}

function addressToBytes(addrHex) {
  const bytes = []
  for (let i = 0; i < 20; i++) {
    bytes.push(parseInt(addrHex.substring(i * 2, i * 2 + 2), 16))
  }
  return bytes
}

// Must match `shared::register_key_message`: pubkey is hex of 56 bytes (x[28 LE] || y[28 LE]).
function buildRegisterMessage(addrLower, pubX, pubY, keyIndex) {
  const bytes = new Uint8Array(56)
  const dv = new DataView(bytes.buffer)
  for (let i = 0; i < 7; i++) {
    dv.setUint32(i * 4, pubX[i], true)
    dv.setUint32(28 + i * 4, pubY[i], true)
  }
  const pubkeyHex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  return [
    'Register KalqiX Session Key',
    '',
    `pubkey: 0x${pubkeyHex}`,
    `account: 0x${addrLower}`,
    `key index: ${keyIndex}`,
    'Only sign this message for a trusted client!',
  ].join('\n')
}

export default function RegisterKeyComponent({
  address,
  wasmReady,
  onRegistered,
}) {
  const [keys, setKeys] = useState(() => KEY_INDICES.map(() => null))
  const [status, setStatus] = useState('')
  const [isError, setIsError] = useState(false)
  const [busy, setBusy] = useState(null)

  const { signMessageAsync } = useSignMessage()

  const loadAllKeys = useCallback(async () => {
    const loaded = await Promise.all(
      KEY_INDICES.map(async (i) => {
        const record = await loadKeyPair(address, i)
        if (!record) return null
        return {
          pubKeyHex: septicPubkeyToHex(
            new Uint32Array(record.pubX),
            new Uint32Array(record.pubY),
          ),
          registered: !!record.registered,
        }
      }),
    )
    setKeys(loaded)
    if (loaded.some((k) => k?.registered)) onRegistered()
  }, [address, onRegistered])

  useEffect(() => {
    loadAllKeys()
  }, [loadAllKeys])

  async function handleRegisterOrRotate(keyIndex) {
    setBusy(keyIndex)
    setStatus('')
    setIsError(false)

    try {
      const existing = keys[keyIndex]

      setStatus(
        existing
          ? `Generating new septic key for index ${keyIndex}...`
          : `Generating septic key for index ${keyIndex}...`,
      )
      const kp = generateSepticKeyPair()
      const pubX = Array.from(kp.pubX)
      const pubY = Array.from(kp.pubY)
      const privLimbs = Array.from(kp.privLimbs)

      await storeKeyPair(address, keyIndex, {
        privLimbs,
        pubX,
        pubY,
        registered: false,
      })

      const addrLower = address.toLowerCase().replace('0x', '')
      const message = buildRegisterMessage(addrLower, pubX, pubY, keyIndex)

      setStatus('Requesting wallet signature...')
      const ethSig = await signMessageAsync({ message })

      setStatus('Sending to backend...')
      const body = {
        account_address: addressToBytes(addrLower),
        key_index: keyIndex,
        pubkey_x: pubX,
        pubkey_y: pubY,
        eth_signature_hex: ethSig.replace('0x', ''),
      }

      const res = await fetch(`${API}/register-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })

      const data = await res.json()

      if (data.success) {
        await markRegistered(address, keyIndex)
        setStatus(
          existing
            ? `Key ${keyIndex} rotated! New root: ${data.new_root}`
            : `Key ${keyIndex} registered! New root: ${data.new_root}`,
        )
        setIsError(false)
        await loadAllKeys()
      } else {
        setStatus(`Error: ${data.error || 'unknown'}`)
        setIsError(true)
      }
    } catch (e) {
      setStatus(`Error: ${e.message}`)
      setIsError(true)
    } finally {
      setBusy(null)
    }
  }

  return (
    <div>
      <h3 style={styles.heading}>Session Keys (Septic Schnorr)</h3>

      {KEY_INDICES.map((i) => {
        const key = keys[i]
        const disabled = busy !== null || !wasmReady
        return (
          <div key={i} style={styles.keyRow}>
            <span style={styles.keyIndex}>Key {i}:</span>
            {key ? (
              <>
                <span style={styles.keyHex}>
                  0x{key.pubKeyHex.substring(0, 16)}...
                  {key.pubKeyHex.substring(key.pubKeyHex.length - 12)}
                </span>
                {key.registered && <span style={styles.badge}>Active</span>}
                <button
                  style={styles.btn}
                  onClick={() => handleRegisterOrRotate(i)}
                  disabled={disabled}
                >
                  {busy === i ? '...' : 'Rotate'}
                </button>
              </>
            ) : (
              <>
                <span style={styles.empty}>
                  {wasmReady ? '(empty)' : '(WASM loading...)'}
                </span>
                <button
                  style={styles.btn}
                  onClick={() => handleRegisterOrRotate(i)}
                  disabled={disabled}
                >
                  {busy === i ? '...' : 'Register'}
                </button>
              </>
            )}
          </div>
        )
      })}

      {status && (
        <div
          style={{
            ...styles.status,
            ...(isError ? styles.error : styles.success),
          }}
        >
          {status}
        </div>
      )}
    </div>
  )
}
