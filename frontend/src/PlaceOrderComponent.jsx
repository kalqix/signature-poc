import { useState, useEffect } from 'react'
import { useSignMessage } from 'wagmi'
import { loadKeyPair, loadP256KeyPair, storeP256KeyPair } from './db.js'
import { bytesToHex } from './utils.js'

const API = 'http://localhost:3001'

const styles = {
  row: { marginBottom: 10 },
  label: { display: 'inline-block', width: 80, fontWeight: 'bold' },
  input: { fontFamily: 'monospace', padding: 4, width: 160 },
  select: { fontFamily: 'monospace', padding: 4 },
  btn: {
    padding: '8px 16px',
    fontFamily: 'monospace',
    fontSize: 14,
    cursor: 'pointer',
    marginTop: 8,
  },
  status: { marginTop: 12, fontSize: 13 },
  error: { color: '#f66' },
  success: { color: '#6c6' },
  orderList: { marginTop: 20, fontSize: 12 },
  orderItem: {
    padding: 8,
    border: '1px solid #444',
    borderRadius: 4,
    marginBottom: 6,
    fontFamily: 'monospace',
  },
  radio: { marginRight: 6 },
  radioLabel: { marginRight: 16, cursor: 'pointer' },
  benchmark: {
    marginTop: 20,
    padding: 12,
    border: '1px solid #555',
    borderRadius: 6,
    fontSize: 13,
    fontFamily: 'monospace',
  },
  benchRow: { marginBottom: 4 },
  reduction: { color: '#6f6', fontWeight: 'bold' },
}

export default function PlaceOrderComponent({ address }) {
  const [keyPair, setKeyPair] = useState(null)
  const [market, setMarket] = useState('ETH/USDC')
  const [side, setSide] = useState('BUY')
  const [price, setPrice] = useState('')
  const [quantity, setQuantity] = useState('')
  const [status, setStatus] = useState('')
  const [isError, setIsError] = useState(false)
  const [orders, setOrders] = useState([])
  const [sigScheme, setSigScheme] = useState('ed25519')
  const [p256KeyPair, setP256KeyPair] = useState(null)
  const [ed25519Cycles, setEd25519Cycles] = useState(null)
  const [secp256k1Cycles, setSecp256k1Cycles] = useState(null)
  const [p256Cycles, setP256Cycles] = useState(null)

  const { signMessageAsync } = useSignMessage()

  useEffect(() => {
    loadKey()
    loadP256Key()
  }, [address])

  async function loadKey() {
    const record = await loadKeyPair(address, 0)
    if (record) setKeyPair(record.keyPair)
  }

  async function loadP256Key() {
    const record = await loadP256KeyPair(address)
    if (record) {
      setP256KeyPair(record.keyPair)
    }
  }

  async function getOrCreateP256KeyPair() {
    if (p256KeyPair) return p256KeyPair
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    )
    const pubKeyBytes = new Uint8Array(
      await crypto.subtle.exportKey('raw', kp.publicKey)
    )
    await storeP256KeyPair(address, kp, pubKeyBytes)
    setP256KeyPair(kp)
    return kp
  }

  function addressToBytes(addrHex) {
    const bytes = []
    for (let i = 0; i < 20; i++) {
      bytes.push(parseInt(addrHex.substring(i * 2, i * 2 + 2), 16))
    }
    return bytes
  }

  async function handlePlaceOrderEd25519() {
    if (!keyPair) {
      setStatus('No session key found')
      setIsError(true)
      return
    }

    const priceNum = parseInt(price, 10)
    const qtyNum = parseInt(quantity, 10)
    const addrLower = address.toLowerCase().replace('0x', '')
    const orderMsg = `${market}:${side}:${priceNum}:${qtyNum}:${addrLower}`
    const msgBytes = new TextEncoder().encode(orderMsg)
    const hash = await crypto.subtle.digest('SHA-256', msgBytes)

    const sigBytes = await crypto.subtle.sign(
      { name: 'Ed25519' },
      keyPair.privateKey,
      new Uint8Array(hash)
    )

    const body = {
      account_address: addressToBytes(addrLower),
      key_index: 0,
      market,
      side,
      price: priceNum,
      quantity: qtyNum,
      ed25519_signature_hex: bytesToHex(new Uint8Array(sigBytes)),
    }

    const res = await fetch(`${API}/place-order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    return res.json()
  }

  async function handlePlaceOrderEth() {
    const priceNum = parseInt(price, 10)
    const qtyNum = parseInt(quantity, 10)
    const addrLower = address.toLowerCase().replace('0x', '')
    const orderMsg = `${market}:${side}:${priceNum}:${qtyNum}:${addrLower}`

    const ethSig = await signMessageAsync({ message: orderMsg })

    const body = {
      account_address: addressToBytes(addrLower),
      key_index: 0,
      market,
      side,
      price: priceNum,
      quantity: qtyNum,
      eth_signature_hex: ethSig.replace('0x', ''),
    }

    const res = await fetch(`${API}/place-order-eth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    return res.json()
  }

  async function handlePlaceOrderP256() {
    const priceNum = parseInt(price, 10)
    const qtyNum = parseInt(quantity, 10)
    const addrLower = address.toLowerCase().replace('0x', '')
    const orderMsg = `${market}:${side}:${priceNum}:${qtyNum}:${addrLower}`
    const msgBytes = new TextEncoder().encode(orderMsg)

    const kp = await getOrCreateP256KeyPair()
    // Web Crypto ECDSA with hash:'SHA-256' hashes msgBytes internally before signing.
    // Guest program uses verify_prehash on SHA-256(message), so pass raw message here.
    const rawSig = new Uint8Array(await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      kp.privateKey,
      msgBytes
    ))

    const pubKeyBytes = new Uint8Array(
      await crypto.subtle.exportKey('raw', kp.publicKey)
    )

    const body = {
      account_address: addressToBytes(addrLower),
      key_index: 0,
      market,
      side,
      price: priceNum,
      quantity: qtyNum,
      p256_signature_hex: bytesToHex(rawSig),
      p256_pubkey_hex: bytesToHex(pubKeyBytes),
    }

    const res = await fetch(`${API}/place-order-p256`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    return res.json()
  }

  async function handlePlaceOrder() {
    const priceNum = parseInt(price, 10)
    const qtyNum = parseInt(quantity, 10)
    if (!priceNum || !qtyNum) {
      setStatus('Price and quantity must be positive integers')
      setIsError(true)
      return
    }

    setStatus('Signing order...')
    setIsError(false)

    try {
      let data
      if (sigScheme === 'ed25519') data = await handlePlaceOrderEd25519()
      else if (sigScheme === 'secp256k1') data = await handlePlaceOrderEth()
      else data = await handlePlaceOrderP256()

      if (data.success) {
        const cycles = data.execution_report?.total_instructions
        const schemeLabels = { ed25519: 'Ed25519', secp256k1: 'secp256k1', p256: 'P-256' }
        const scheme = schemeLabels[sigScheme]
        setStatus(`Order proved (${scheme})! ${cycles ? cycles.toLocaleString() + ' instructions' : ''}`)
        setIsError(false)

        if (sigScheme === 'ed25519' && cycles) setEd25519Cycles(cycles)
        if (sigScheme === 'secp256k1' && cycles) setSecp256k1Cycles(cycles)
        if (sigScheme === 'p256' && cycles) setP256Cycles(cycles)

        setOrders((prev) => [
          {
            market,
            side,
            price: priceNum,
            quantity: qtyNum,
            time: new Date().toLocaleTimeString(),
            scheme,
            cycles,
          },
          ...prev,
        ])
        setPrice('')
        setQuantity('')
      } else {
        setStatus(`Error: ${data.error || 'unknown'}`)
        setIsError(true)
      }
    } catch (e) {
      setStatus(`Error: ${e.message}`)
      setIsError(true)
    }
  }

  const reductionVsEth =
    ed25519Cycles && secp256k1Cycles
      ? ((1 - ed25519Cycles / secp256k1Cycles) * 100).toFixed(1)
      : null
  const reductionVsP256 =
    ed25519Cycles && p256Cycles
      ? ((1 - ed25519Cycles / p256Cycles) * 100).toFixed(1)
      : null

  return (
    <div>
      <h3>Place Order</h3>

      <div style={styles.row}>
        <span style={styles.label}>Signing</span>
        <label style={styles.radioLabel}>
          <input
            type="radio"
            name="sigScheme"
            value="ed25519"
            checked={sigScheme === 'ed25519'}
            onChange={() => setSigScheme('ed25519')}
            style={styles.radio}
          />
          Ed25519 (session key)
        </label>
        <label style={styles.radioLabel}>
          <input
            type="radio"
            name="sigScheme"
            value="secp256k1"
            checked={sigScheme === 'secp256k1'}
            onChange={() => setSigScheme('secp256k1')}
            style={styles.radio}
          />
          Ethereum personal_sign
        </label>
        <label style={styles.radioLabel}>
          <input
            type="radio"
            name="sigScheme"
            value="p256"
            checked={sigScheme === 'p256'}
            onChange={() => setSigScheme('p256')}
            style={styles.radio}
          />
          P-256 ECDSA
        </label>
      </div>

      <div style={styles.row}>
        <span style={styles.label}>Market</span>
        <select style={styles.select} value={market} onChange={(e) => setMarket(e.target.value)}>
          <option>ETH/USDC</option>
          <option>BTC/USDC</option>
        </select>
      </div>

      <div style={styles.row}>
        <span style={styles.label}>Side</span>
        <select style={styles.select} value={side} onChange={(e) => setSide(e.target.value)}>
          <option>BUY</option>
          <option>SELL</option>
        </select>
      </div>

      <div style={styles.row}>
        <span style={styles.label}>Price</span>
        <input
          style={styles.input}
          type="number"
          value={price}
          onChange={(e) => setPrice(e.target.value)}
          placeholder="e.g. 2000000"
        />
      </div>

      <div style={styles.row}>
        <span style={styles.label}>Quantity</span>
        <input
          style={styles.input}
          type="number"
          value={quantity}
          onChange={(e) => setQuantity(e.target.value)}
          placeholder="e.g. 100"
        />
      </div>

      <button style={styles.btn} onClick={handlePlaceOrder}>
        Place Order
      </button>

      {status && (
        <div style={{ ...styles.status, ...(isError ? styles.error : styles.success) }}>
          {status}
        </div>
      )}

      {(ed25519Cycles || secp256k1Cycles || p256Cycles) && (
        <div style={styles.benchmark}>
          <strong>Benchmark</strong>
          {ed25519Cycles && (
            <div style={styles.benchRow}>
              Ed25519 + SHA-256: {ed25519Cycles.toLocaleString()} instructions
            </div>
          )}
          {secp256k1Cycles && (
            <div style={styles.benchRow}>
              secp256k1 + keccak256: {secp256k1Cycles.toLocaleString()} instructions
            </div>
          )}
          {p256Cycles && (
            <div style={styles.benchRow}>
              P-256 + SHA-256: {p256Cycles.toLocaleString()} instructions
            </div>
          )}
          {reductionVsEth && (
            <div style={styles.benchRow}>
              <span style={styles.reduction}>
                Ed25519 vs secp256k1: {reductionVsEth}% reduction
              </span>
            </div>
          )}
          {reductionVsP256 && (
            <div style={styles.benchRow}>
              <span style={styles.reduction}>
                Ed25519 vs P-256: {reductionVsP256}% reduction
              </span>
            </div>
          )}
        </div>
      )}

      {orders.length > 0 && (
        <div style={styles.orderList}>
          <h4>Order History</h4>
          {orders.map((o, i) => (
            <div key={i} style={styles.orderItem}>
              {o.time} — {o.scheme} — {o.side} {o.quantity} {o.market} @ {o.price}
              {o.cycles ? ` (${o.cycles.toLocaleString()} instr)` : ''}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
