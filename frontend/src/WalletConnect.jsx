import { useAccount, useConnect, useDisconnect } from 'wagmi'

const styles = {
  btn: {
    padding: '8px 16px',
    fontFamily: 'monospace',
    fontSize: 14,
    cursor: 'pointer',
    marginRight: 8,
  },
  address: {
    fontSize: 13,
    color: '#888',
    marginTop: 8,
    wordBreak: 'break-all',
  },
}

export default function WalletConnect() {
  const { address, isConnected } = useAccount()
  const { connect, connectors } = useConnect()
  const { disconnect } = useDisconnect()

  if (isConnected) {
    return (
      <div>
        <button style={styles.btn} onClick={() => disconnect()}>
          Disconnect
        </button>
        <div style={styles.address}>Connected: {address}</div>
      </div>
    )
  }

  return (
    <div>
      {connectors.map((connector) => (
        <button
          key={connector.uid}
          style={styles.btn}
          onClick={() => connect({ connector })}
        >
          Connect {connector.name}
        </button>
      ))}
    </div>
  )
}
