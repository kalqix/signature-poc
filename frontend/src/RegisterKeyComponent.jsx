import { useState, useEffect, useCallback } from 'react'
import { useSignMessage } from 'wagmi'
import { loadKeyPair, storeKeyPair, markRegistered } from './db.js'
import { bytesToHex } from './utils.js'

const API = 'http://localhost:3001'
const KEY_INDICES = [0, 1, 2, 3, 4]

const styles = {
  heading: { marginBottom: 12 },
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

export default function RegisterKeyComponent({ address, onRegistered }) {
  // keys[i] = { pubKeyHex, registered } or null
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
          pubKeyHex: bytesToHex(new Uint8Array(record.pubKey)),
          registered: !!record.registered,
        }
      })
    )
    setKeys(loaded)
    if (loaded.some((k) => k?.registered)) onRegistered()
  }, [address, onRegistered])

  useEffect(() => {
    loadAllKeys()
  }, [loadAllKeys])

  function addressToBytes(addrHex) {
    const bytes = []
    for (let i = 0; i < 20; i++) {
      bytes.push(parseInt(addrHex.substring(i * 2, i * 2 + 2), 16))
    }
    return bytes
  }

  async function generateAndStore(keyIndex) {
    const kp = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      false,
      ['sign', 'verify']
    )
    const pubKeyBytes = await crypto.subtle.exportKey('raw', kp.publicKey)
    await storeKeyPair(address, keyIndex, kp, pubKeyBytes, false)
    return bytesToHex(new Uint8Array(pubKeyBytes))
  }

  async function handleRegisterOrRotate(keyIndex) {
    setBusy(keyIndex)
    setStatus('')
    setIsError(false)

    try {
      const existing = keys[keyIndex]
      let pubHex

      if (!existing) {
        // Fresh: generate key first
        setStatus(`Generating key ${keyIndex}...`)
        pubHex = await generateAndStore(keyIndex)
      } else {
        // Rotation: generate NEW key, overwrite old
        setStatus(`Generating new key for index ${keyIndex}...`)
        pubHex = await generateAndStore(keyIndex)
      }

      const addrLower = address.toLowerCase().replace('0x', '')
      const message = [
        'Register KalqiX Session Key',
        '',
        `pubkey: 0x${pubHex}`,
        `account: 0x${addrLower}`,
        `key index: ${keyIndex}`,
        'Only sign this message for a trusted client!',
      ].join('\n')

      setStatus('Requesting wallet signature...')
      const ethSig = await signMessageAsync({ message })

      setStatus('Sending to backend...')
      const body = {
        account_address: addressToBytes(addrLower),
        key_index: keyIndex,
        pubkey_hex: pubHex,
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
            : `Key ${keyIndex} registered! New root: ${data.new_root}`
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
      <h3 style={styles.heading}>Session Keys</h3>

      {KEY_INDICES.map((i) => {
        const key = keys[i]
        return (
          <div key={i} style={styles.keyRow}>
            <span style={styles.keyIndex}>Key {i}:</span>
            {key ? (
              <>
                <span style={styles.keyHex}>
                  0x{key.pubKeyHex.substring(0, 16)}...{key.pubKeyHex.substring(48)}
                </span>
                {key.registered && <span style={styles.badge}>Active</span>}
                <button
                  style={styles.btn}
                  onClick={() => handleRegisterOrRotate(i)}
                  disabled={busy !== null}
                >
                  {busy === i ? '...' : 'Rotate'}
                </button>
              </>
            ) : (
              <>
                <span style={styles.empty}>(empty)</span>
                <button
                  style={styles.btn}
                  onClick={() => handleRegisterOrRotate(i)}
                  disabled={busy !== null}
                >
                  {busy === i ? '...' : 'Register'}
                </button>
              </>
            )}
          </div>
        )
      })}

      {status && (
        <div style={{ ...styles.status, ...(isError ? styles.error : styles.success) }}>
          {status}
        </div>
      )}
    </div>
  )
}
