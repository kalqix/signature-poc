import { useState } from 'react'
import { useSignMessage } from 'wagmi'
import { loadKeyPair } from './db.js'
import { signSepticOrder } from './septic.js'

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

function addressToBytes(addrHex) {
  const bytes = []
  for (let i = 0; i < 20; i++) {
    bytes.push(parseInt(addrHex.substring(i * 2, i * 2 + 2), 16))
  }
  return bytes
}

export default function PlaceOrderComponent({ address, wasmReady }) {
  const [market, setMarket] = useState('ETH/USDC')
  const [side, setSide] = useState('BUY')
  const [price, setPrice] = useState('')
  const [quantity, setQuantity] = useState('')
  const [status, setStatus] = useState('')
  const [isError, setIsError] = useState(false)
  const [orders, setOrders] = useState([])
  const [sigScheme, setSigScheme] = useState('septic')
  const [septicCycles, setSepticCycles] = useState(null)
  const [secp256k1Cycles, setSecp256k1Cycles] = useState(null)

  const { signMessageAsync } = useSignMessage()

  async function handlePlaceOrderSeptic() {
    const record = await loadKeyPair(address, 0)
    if (!record || !record.registered) {
      setStatus('No registered session key for index 0 — register one above.')
      setIsError(true)
      return null
    }

    const priceNum = parseInt(price, 10)
    const qtyNum = parseInt(quantity, 10)
    const addrLower = address.toLowerCase().replace('0x', '')
    const orderMsg = `${market}:${side}:${priceNum}:${qtyNum}:${addrLower}`

    const started = performance.now()
    const sig = signSepticOrder(
      new Uint32Array(record.privLimbs),
      new Uint32Array(record.pubX),
      new Uint32Array(record.pubY),
      orderMsg,
    )
    const elapsed = (performance.now() - started).toFixed(0)

    const body = {
      account_address: addressToBytes(addrLower),
      key_index: 0,
      market,
      side,
      price: priceNum,
      quantity: qtyNum,
      signature_r_x: Array.from(sig.rX),
      signature_r_y: Array.from(sig.rY),
      signature_s: Array.from(sig.s),
      challenge_e: Array.from(sig.challengeE),
    }

    const res = await fetch(`${API}/place-order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const data = await res.json()
    return { ...data, _signTimeMs: elapsed }
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
      const data =
        sigScheme === 'septic'
          ? await handlePlaceOrderSeptic()
          : await handlePlaceOrderEth()

      if (!data) return

      if (data.success) {
        const cycles = data.execution_report?.total_instructions
        const scheme =
          sigScheme === 'septic' ? 'Septic Schnorr' : 'secp256k1'
        const signSuffix = data._signTimeMs
          ? ` (sign: ${data._signTimeMs}ms)`
          : ''
        setStatus(
          `Order proved (${scheme})! ${
            cycles ? cycles.toLocaleString() + ' instructions' : ''
          }${signSuffix}`,
        )
        setIsError(false)

        if (sigScheme === 'septic' && cycles) setSepticCycles(cycles)
        if (sigScheme === 'secp256k1' && cycles) setSecp256k1Cycles(cycles)

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

  const septicVsEth =
    septicCycles && secp256k1Cycles
      ? ((1 - septicCycles / secp256k1Cycles) * 100).toFixed(1)
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
            value="septic"
            checked={sigScheme === 'septic'}
            onChange={() => setSigScheme('septic')}
            disabled={!wasmReady}
            style={styles.radio}
          />
          Septic Schnorr {wasmReady ? '(session key)' : '(loading WASM)'}
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

      {(septicCycles || secp256k1Cycles) && (
        <div style={styles.benchmark}>
          <strong>Benchmark</strong>
          {septicCycles && (
            <div style={styles.benchRow}>
              Septic Schnorr + Merkle: {septicCycles.toLocaleString()} instructions
            </div>
          )}
          {secp256k1Cycles && (
            <div style={styles.benchRow}>
              secp256k1 + keccak256: {secp256k1Cycles.toLocaleString()} instructions
            </div>
          )}
          {septicVsEth && (
            <div style={styles.benchRow}>
              <span style={styles.reduction}>
                Septic Schnorr vs secp256k1: {septicVsEth}% reduction
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
