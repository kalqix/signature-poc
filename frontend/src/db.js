const DB_NAME = 'kalqix_poc'
const STORE_NAME = 'session_keys'
const DB_VERSION = 2

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME)
      }
      // Delete old store from v1 if it exists
      if (db.objectStoreNames.contains('keys')) {
        db.deleteObjectStore('keys')
      }
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

export async function loadKeyPair(address, keyIndex) {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly')
    const store = tx.objectStore(STORE_NAME)
    const req = store.get(`kalqix_ed25519_${address.toLowerCase()}_${keyIndex}`)
    req.onsuccess = () => resolve(req.result || null)
    req.onerror = () => reject(req.error)
  })
}

export async function storeKeyPair(address, keyIndex, keyPair, pubKeyBytes, registered = false) {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    const store = tx.objectStore(STORE_NAME)
    const req = store.put(
      { keyPair, pubKey: pubKeyBytes, registered },
      `kalqix_ed25519_${address.toLowerCase()}_${keyIndex}`
    )
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error)
  })
}

export async function markRegistered(address, keyIndex) {
  const record = await loadKeyPair(address, keyIndex)
  if (record) {
    await storeKeyPair(address, keyIndex, record.keyPair, record.pubKey, true)
  }
}
