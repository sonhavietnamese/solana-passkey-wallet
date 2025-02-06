import crypto from 'crypto'
// First, let's create helper functions to handle different formats
const bufferToHex = (buffer: ArrayBuffer) => {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

const hexToBuffer = (hex: string) => {
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 0x10))).buffer
}

// Function to verify WebAuthn signature
async function verifyWebAuthnSignature(publicKeyHex: string, signatureHex: string, message: string) {
  try {
    // 1. Convert public key from hex to proper format
    // The '04' prefix indicates uncompressed point format
    if (!publicKeyHex.startsWith('04')) {
      throw new Error('Invalid public key format - must start with 04')
    }

    // 2. Create the proper key object
    const keyData = hexToBuffer(publicKeyHex)
    const publicKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      {
        name: 'ECDSA',
        namedCurve: 'P-256', // WebAuthn uses P-256 curve
      },
      true,
      ['verify'],
    )

    // 3. Convert message to buffer
    const messageBuffer = new TextEncoder().encode(message)

    // 4. Convert DER signature to raw format
    // WebAuthn uses DER format (starts with '30')
    if (!signatureHex.startsWith('30')) {
      throw new Error('Invalid signature format - must be DER encoded')
    }
    const signatureBuffer = hexToBuffer(signatureHex)

    // 5. Parse DER signature to get R and S values
    function parseDERSignature(derSignature: ArrayBuffer) {
      const sig = new Uint8Array(derSignature)

      // Basic DER checking
      if (sig[0] !== 0x30) throw new Error('Invalid signature format')

      let pos = 2
      // Get R value
      if (sig[pos] !== 0x02) throw new Error('Invalid R value')
      const rLength = sig[pos + 1]
      pos += 2
      const r = sig.slice(pos, pos + rLength)
      pos += rLength

      // Get S value
      if (sig[pos] !== 0x02) throw new Error('Invalid S value')
      const sLength = sig[pos + 1]
      pos += 2
      const s = sig.slice(pos, pos + sLength)

      // Combine R and S into raw signature
      const rawSignature = new Uint8Array(64)
      rawSignature.set(r.length === 32 ? r : r.slice(-32), 0)
      rawSignature.set(s.length === 32 ? s : s.slice(-32), 32)

      return rawSignature.buffer
    }

    const rawSignature = parseDERSignature(signatureBuffer)

    // 6. Verify the signature
    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }, // WebAuthn uses SHA-256
      },
      publicKey,
      rawSignature,
      messageBuffer,
    )

    return isValid
  } catch (error) {
    console.error('Verification error:', error)
    return false
  }
}

// Example usage:
const verify = async () => {
  const publicKeyHex =
    '04cba20aa6ccb506abbd41921a6184dec13cb45bcac6d77e51dddb5eeaad1d077adf5984b8d339272e3b5d861bc11ebbbebed5f144a2be67f41e3753071c67985a' // Your 65-byte public key hex
  const signatureHex =
    '3045022044f8bb65ea073d53a60e8f60988f15faff083b663efbdc9fa454f555e93102c802210097d8c8c6b383bc4f6afb5bb077857e5e08fcea51e6cdd723a9331b21bb513603' // Your DER signature hex
  const message = 'hello'

  const isValid = await verifyWebAuthnSignature(publicKeyHex, signatureHex, message)

  console.log('Signature is', isValid ? 'valid' : 'invalid')
}

verify()
