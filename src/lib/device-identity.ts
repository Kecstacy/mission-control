/**
 * PATCH: Device Identity Security Enhancement
 * Addresses GitHub Issue #574 - Ed25519 private key stored in plaintext localStorage
 * 
 * This patch migrates from plaintext localStorage to WebCrypto non-extractable keys
 * stored in IndexedDB with proper error handling and fallback.
 */

// ── IndexedDB Storage Layer ──────────────────────────────────────

const DB_NAME = 'mc-device-identity'
const DB_VERSION = 1
const KEY_STORE = 'keys'

/**
 * Opens IndexedDB for key storage
 */
async function openKeyDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    
    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)
    
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result
      if (!db.objectStoreNames.contains(KEY_STORE)) {
        db.createObjectStore(KEY_STORE)
      }
    }
  })
}

/**
 * Stores a CryptoKey in IndexedDB (non-extractable)
 */
async function storeKey(keyName: string, key: CryptoKey): Promise<void> {
  const db = await openKeyDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, 'readwrite')
    const store = tx.objectStore(KEY_STORE)
    const request = store.put(key, keyName)
    
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    
    tx.oncomplete = () => db.close()
  })
}

/**
 * Retrieves a CryptoKey from IndexedDB
 */
async function retrieveKey(keyName: string): Promise<CryptoKey | null> {
  const db = await openKeyDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, 'readonly')
    const store = tx.objectStore(KEY_STORE)
    const request = store.get(keyName)
    
    request.onsuccess = () => resolve(request.result || null)
    request.onerror = () => reject(request.error)
    
    tx.oncomplete = () => db.close()
  })
}

/**
 * Deletes a key from IndexedDB
 */
async function deleteKey(keyName: string): Promise<void> {
  const db = await openKeyDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, 'readwrite')
    const store = tx.objectStore(KEY_STORE)
    const request = store.delete(keyName)
    
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    
    tx.oncomplete = () => db.close()
  })
}

// ── Migrated Device Identity ─────────────────────────────────────

const STORAGE_DEVICE_ID = 'mc-device-id'
const STORAGE_PUBKEY = 'mc-device-pubkey'  // Public key stays in localStorage (it's public)
const STORAGE_DEVICE_TOKEN = 'mc-device-token'
const STORAGE_GATEWAY_URL = 'mc-gateway-url'
const STORAGE_KEY_VERSION = 'mc-key-version' // Track key storage version for migration

const CURRENT_KEY_VERSION = '2' // v2 = IndexedDB storage

export interface SecureDeviceIdentity {
  deviceId: string
  publicKeyBase64: string
  privateKey: CryptoKey // Non-extractable CryptoKey from IndexedDB
}

// ── Helpers (unchanged) ──────────────────────────────────────────

function toBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(buffer))
  const bytes = new Uint8Array(digest)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// ── Migration from localStorage v1 to IndexedDB v2 ──────────────

/**
 * Migrates plaintext private key from localStorage to non-extractable IndexedDB key
 * This is a one-time operation that runs on first load after upgrade
 */
async function migrateFromV1(): Promise<SecureDeviceIdentity | null> {
  // Check if there's a v1 key in localStorage
  const storedPriv = localStorage.getItem('mc-device-privkey') // Legacy key
  if (!storedPriv) return null
  
  // Check if already migrated
  const keyVersion = localStorage.getItem(STORAGE_KEY_VERSION)
  if (keyVersion === CURRENT_KEY_VERSION) return null
  
  try {
    // Import the existing key
    const pkcs8Bytes = base64UrlToBytes(storedPriv)
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8Bytes,
      'Ed25519',
      false, // non-extractable!
      ['sign']
    )
    
    const storedId = localStorage.getItem(STORAGE_DEVICE_ID)
    const storedPub = localStorage.getItem(STORAGE_PUBKEY)
    
    if (!storedId || !storedPub) return null
    
    // Store private key in IndexedDB
    await storeKey('private-key', privateKey)
    
    // Mark migration complete
    localStorage.setItem(STORAGE_KEY_VERSION, CURRENT_KEY_VERSION)
    
    // Remove plaintext private key from localStorage
    localStorage.removeItem('mc-device-privkey')
    
    return {
      deviceId: storedId,
      publicKeyBase64: storedPub,
      privateKey
    }
  } catch (error) {
    console.error('Migration from v1 failed:', error)
    return null
  }
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

// ── Key Generation (non-extractable) ─────────────────────────────

async function createNewSecureIdentity(): Promise<SecureDeviceIdentity> {
  // Generate key pair with extractable: false for private key
  const keyPair = await crypto.subtle.generateKey(
    'Ed25519',
    false, // non-extractable - private key cannot be exported!
    ['sign', 'verify']
  )

  const pubRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey)
  // Note: We do NOT export the private key - it stays non-extractable in memory/IndexedDB

  const deviceId = await sha256Hex(pubRaw)
  const publicKeyBase64 = toBase64Url(pubRaw)

  // Store only the public key in localStorage (it's public anyway)
  localStorage.setItem(STORAGE_DEVICE_ID, deviceId)
  localStorage.setItem(STORAGE_PUBKEY, publicKeyBase64)
  localStorage.setItem(STORAGE_KEY_VERSION, CURRENT_KEY_VERSION)

  // Store the private key in IndexedDB (non-extractable CryptoKey)
  await storeKey('private-key', keyPair.privateKey)

  return {
    deviceId,
    publicKeyBase64,
    privateKey: keyPair.privateKey,
  }
}

// ── Public API ───────────────────────────────────────────────────

/**
 * Returns existing device identity or generates a new one.
 * Private key is stored as non-extractable CryptoKey in IndexedDB.
 */
export async function getOrCreateSecureDeviceIdentity(): Promise<SecureDeviceIdentity> {
  // Try migration from v1 first
  const migrated = await migrateFromV1()
  if (migrated) return migrated
  
  const storedId = localStorage.getItem(STORAGE_DEVICE_ID)
  const storedPub = localStorage.getItem(STORAGE_PUBKEY)
  const keyVersion = localStorage.getItem(STORAGE_KEY_VERSION)
  
  if (storedId && storedPub && keyVersion === CURRENT_KEY_VERSION) {
    // Try to retrieve private key from IndexedDB
    const privateKey = await retrieveKey('private-key')
    if (privateKey) {
      return {
        deviceId: storedId,
        publicKeyBase64: storedPub,
        privateKey
      }
    }
  }

  // Corrupted or missing keys - regenerate
  return createNewSecureIdentity()
}

/**
 * Signs an auth payload with the Ed25519 private key.
 * The private key never leaves the secure context.
 */
export async function signPayloadSecure(
  privateKey: CryptoKey,
  payload: string,
  signedAt = Date.now()
): Promise<{ signature: string; signedAt: number }> {
  const encoder = new TextEncoder()
  const payloadBytes = encoder.encode(payload)
  const signatureBuffer = await crypto.subtle.sign('Ed25519', privateKey, payloadBytes)
  return {
    signature: toBase64Url(signatureBuffer),
    signedAt,
  }
}

/** Reads cached device token (this is fine in localStorage) */
export function getCachedDeviceToken(): string | null {
  return localStorage.getItem(STORAGE_DEVICE_TOKEN)
}

/** Caches the device token */
export function cacheDeviceToken(token: string): void {
  localStorage.setItem(STORAGE_DEVICE_TOKEN, token)
}

/** Clears ALL device identity data including IndexedDB keys */
export async function clearSecureDeviceIdentity(): Promise<void> {
  localStorage.removeItem(STORAGE_DEVICE_ID)
  localStorage.removeItem(STORAGE_PUBKEY)
  localStorage.removeItem(STORAGE_DEVICE_TOKEN)
  localStorage.removeItem(STORAGE_KEY_VERSION)
  
  // Clear IndexedDB keys
  try {
    await deleteKey('private-key')
  } catch {
    // Best effort
  }
}

/**
 * Check if device is using secure key storage (v2+)
 */
export function isSecureKeyStorage(): boolean {
  return localStorage.getItem(STORAGE_KEY_VERSION) === CURRENT_KEY_VERSION
}

/**
 * Force re-key with secure storage (for migration testing)
 */
export async function forceRekey(): Promise<SecureDeviceIdentity> {
  // Clear everything
  await clearSecureDeviceIdentity()
  // Generate new secure identity
  return createNewSecureIdentity()
}
