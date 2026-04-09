import { useAccount } from 'wagmi'
import WalletConnect from './WalletConnect.jsx'
import RegisterKeyComponent from './RegisterKeyComponent.jsx'
import PlaceOrderComponent from './PlaceOrderComponent.jsx'
import { useState, useEffect } from 'react'

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
  error: {
    color: '#f66',
    padding: 20,
    textAlign: 'center',
  },
}

async function checkEd25519Support() {
  try {
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign'])
    return true
  } catch {
    return false
  }
}

export default function App() {
  const { address, isConnected } = useAccount()
  const [keyRegistered, setKeyRegistered] = useState(false)
  const [ed25519Supported, setEd25519Supported] = useState(null)

  useEffect(() => {
    checkEd25519Support().then(setEd25519Supported)
  }, [])

  if (ed25519Supported === null) return null

  if (!ed25519Supported) {
    return (
      <div style={styles.container}>
        <h1 style={styles.title}>KalqiX Signature POC</h1>
        <div style={styles.error}>
          Ed25519 Web Crypto not supported in this browser.
          <br />
          Use Chrome 113+ or Firefox 113+.
        </div>
      </div>
    )
  }

  return (
    <div style={styles.container}>
      <h1 style={styles.title}>KalqiX Signature POC</h1>

      <WalletConnect />

      {isConnected && (
        <div style={styles.section}>
          <RegisterKeyComponent
            address={address}
            onRegistered={() => setKeyRegistered(true)}
          />
        </div>
      )}

      {isConnected && keyRegistered && (
        <div style={styles.section}>
          <PlaceOrderComponent address={address} />
        </div>
      )}
    </div>
  )
}
