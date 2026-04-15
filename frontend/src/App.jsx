import { useAccount } from 'wagmi'
import WalletConnect from './WalletConnect.jsx'
import RegisterKeyComponent from './RegisterKeyComponent.jsx'
import PlaceOrderComponent from './PlaceOrderComponent.jsx'
import { useState, useEffect } from 'react'
import { initWasm } from './septic.js'

const styles = {
  container: {
    maxWidth: 640,
    margin: '40px auto',
    fontFamily: 'monospace',
    padding: '0 20px',
  },
  title: {
    fontSize: 24,
    marginBottom: 24,
  },
  section: {
    marginTop: 32,
    padding: 16,
    border: '1px solid #333',
    borderRadius: 8,
  },
  warning: {
    marginTop: 16,
    padding: 12,
    border: '1px solid #aa4',
    borderRadius: 6,
    background: '#221',
    color: '#dd8',
    fontSize: 13,
  },
}

export default function App() {
  const { address, isConnected } = useAccount()
  const [keyRegistered, setKeyRegistered] = useState(false)
  const [wasmReady, setWasmReady] = useState(false)
  const [wasmError, setWasmError] = useState(null)

  useEffect(() => {
    initWasm()
      .then(() => setWasmReady(true))
      .catch((e) => setWasmError(e.message || String(e)))
  }, [])

  return (
    <div style={styles.container}>
      <h1 style={styles.title}>KalqiX Signature POC</h1>

      <WalletConnect />

      {wasmError && (
        <div style={styles.warning}>
          Septic WASM failed to load: {wasmError}. Run{' '}
          <code>wasm-pack build --target web --out-dir ../src/wasm-pkg</code>{' '}
          in <code>frontend/wasm-signer</code>.
        </div>
      )}

      {isConnected && (
        <div style={styles.section}>
          <RegisterKeyComponent
            address={address}
            wasmReady={wasmReady}
            onRegistered={() => setKeyRegistered(true)}
          />
        </div>
      )}

      {isConnected && keyRegistered && (
        <div style={styles.section}>
          <PlaceOrderComponent address={address} wasmReady={wasmReady} />
        </div>
      )}
    </div>
  )
}
