// Helper functions
const bufferToHex = (buffer) => {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

const hexToBuffer = (hex) => {
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 0x10))).buffer
}

// Function to verify WebAuthn signature
async function verifyWebAuthnSignature(publicKeyHex, signatureHex, message) {
  try {
    // 1. Convert public key from hex to proper format
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
        namedCurve: 'P-256',
      },
      true,
      ['verify'],
    )

    // 3. Create clientDataHash (this is what WebAuthn actually signs)
    const encoder = new TextEncoder()
    const clientData = {
      type: 'webauthn.get',
      challenge: bufferToHex(encoder.encode(message)),
      origin: window.location.origin,
    }
    const clientDataJSON = JSON.stringify(clientData)
    const clientDataHash = await crypto.subtle.digest('SHA-256', encoder.encode(clientDataJSON))

    // 4. Convert DER signature to raw format
    if (!signatureHex.startsWith('30')) {
      throw new Error('Invalid signature format - must be DER encoded')
    }
    const signatureBuffer = hexToBuffer(signatureHex)

    // 5. Parse DER signature
    function parseDERSignature(derSignature) {
      const sig = new Uint8Array(derSignature)

      if (sig[0] !== 0x30) throw new Error('Invalid signature format')

      let pos = 2
      if (sig[pos] !== 0x02) throw new Error('Invalid R value')
      const rLength = sig[pos + 1]
      pos += 2
      const r = sig.slice(pos, pos + rLength)
      pos += rLength

      if (sig[pos] !== 0x02) throw new Error('Invalid S value')
      const sLength = sig[pos + 1]
      pos += 2
      const s = sig.slice(pos, pos + sLength)

      const rawSignature = new Uint8Array(64)
      rawSignature.set(r.length === 32 ? r : r.slice(-32), 0)
      rawSignature.set(s.length === 32 ? s : s.slice(-32), 32)

      return rawSignature.buffer
    }

    // adhoc
    const baseSignatureHex = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    const baseSignatureBuffer = hexToBuffer(baseSignatureHex)

    const rawSignature = parseDERSignature(signatureBuffer)

    // 6. Verify the signature with the clientDataHash
    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      publicKey,
      rawSignature,
      baseSignatureBuffer,
    )

    return isValid
  } catch (error) {
    console.error('Verification error:', error)
    return false
  }
}

// Example usage with your passkey values
const verifyPasskey = async () => {
  const publicKeyHex =
    '04be30b419149cc0c2411a1bd6f9c5164369c02d108a10e2bbc1223c349f3fc1a70d3d79af2458ceac5aa98f23a4b27a10ff6c1f02e52da2e9b0c0277e85cba0e7'
  const signatureHex =
    '304402204f3e8d22acf65f39d61da71796eaf7d397ff6011cf23a1a000f21d29515db8b102204d1678eff1ce362649286e253f3686ffd0c72c7c43a7034c1926fb4db7370f34'
  const message = 'hello'

  const isValid = await verifyWebAuthnSignature(publicKeyHex, signatureHex, message)

  console.log('Passkey signature is', isValid ? 'valid' : 'invalid')
}

verifyPasskey()
