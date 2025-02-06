import { startAuthentication, startRegistration } from '@simplewebauthn/browser'

export default function Attempt01() {
  const registerPasskey = async () => {
    try {
      const name = 'user_id' + Date.now()
      // This options should come from your server
      const options = {
        challenge: 'your_challenge_here',
        rp: {
          name: 'Your App',
          id: window.location.hostname,
        },
        user: {
          id: name,
          name: name,
          displayName: name,
        },
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7, // ES256 (ECDSA with P-256 and SHA-256)
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          residentKey: 'required',
          userVerification: 'required',
        },
      }

      const result = await startRegistration(options)

      // Extract and convert public key to hex
      const publicKeyBytes = result.response.publicKey
      console.log('Public Key (base64):', publicKeyBytes)

      if (!publicKeyBytes) {
        throw new Error('Public key is missing')
      }

      // Convert base64url to base64
      const base64 = publicKeyBytes.replace(/-/g, '+').replace(/_/g, '/')

      // Decode base64 string to bytes
      const binaryString = atob(base64)
      const bytes = new Uint8Array(binaryString.length)
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i)
      }

      // Skip the ASN.1 header (26 bytes) - no need to prepend '04' as it's already included
      const rawKeyBytes = bytes.slice(26)
      const publicKeyHex = Array.from(rawKeyBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')

      console.log('Public Key (hex for Rust):', publicKeyHex)
    } catch (error) {
      console.error('Error:', error)
    }
  }

  const signMessage = async () => {
    try {
      // Convert "hello" to Uint8Array and create a challenge
      const message = new TextEncoder().encode('hello')
      const messageHex = Array.from(message)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
      console.log('Message to sign (hex):', messageHex) // Will show: 68656c6c6f

      const options = {
        challenge: messageHex, // Using message as challenge
        allowCredentials: [], // Empty array to allow any credential
        userVerification: 'required',
      }

      const result = await startAuthentication(options)

      // Extract and convert signature to hex
      const signature = result.response.signature
      console.log('Raw signature:', result.response)
      console.log('Signature (base64):', signature)

      if (!signature) {
        throw new Error('Signature is missing')
      }

      // Convert base64url to base64
      const sigBase64 = signature.replace(/-/g, '+').replace(/_/g, '/')

      // Decode base64 string to bytes
      const sigBinaryString = atob(sigBase64)
      const sigBytes = new Uint8Array(sigBinaryString.length)
      for (let i = 0; i < sigBinaryString.length; i++) {
        sigBytes[i] = sigBinaryString.charCodeAt(i)
      }

      // Convert to hex for debugging
      const signatureHex = Array.from(sigBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
      console.log('Full signature (hex):', signatureHex)

      // The WebAuthn signature is in DER format
      // Format: 30 44 02 20 (32 bytes for R) 02 20 (32 bytes for S)
      // We need to extract R and S values
      const rStart = 4 // Skip 30 44 02 20
      const rLength = 32
      const sStart = rStart + rLength + 2 // Skip 02 20
      const sLength = 32

      const rBytes = sigBytes.slice(rStart, rStart + rLength)
      const sBytes = sigBytes.slice(sStart, sStart + sLength)

      // Format R and S as hex strings
      const rHex = Array.from(rBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
      const sHex = Array.from(sBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')

      console.log('R value (hex):', rHex)
      console.log('S value (hex):', sHex)

      // Format signature for Rust code (concatenated R and S)
      const rustSignatureHex = rHex + sHex
      console.log('Signature for Rust (hex):', rustSignatureHex)

      console.log('ClientDataJSON:', result.response.clientDataJSON)
      // Also log the authenticator data for debugging
      console.log('AuthenticatorData:', result.response.authenticatorData)
    } catch (error) {
      console.error('Error:', error)
    }
  }

  const verifySignature = async (message: string, signatureHex: string, publicKeyHex: string) => {
    try {
      // Convert message to bytes
      const messageBytes = new TextEncoder().encode(message)

      // Convert hex strings to Uint8Arrays
      const signatureBytes = new Uint8Array(signatureHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [])
      const publicKeyBytes = new Uint8Array(publicKeyHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [])

      // Import the public key
      const publicKey = await crypto.subtle.importKey(
        'raw',
        publicKeyBytes,
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        true,
        ['verify'],
      )

      // Verify the signature
      const isValid = await crypto.subtle.verify(
        {
          name: 'ECDSA',
          hash: { name: 'SHA-256' },
        },
        publicKey,
        signatureBytes,
        messageBytes,
      )

      console.log('Signature is valid:', isValid)

      return isValid
    } catch (error) {
      console.error('Error verifying signature:', error)
      return false
    }
  }

  return (
    <div>
      <button onClick={registerPasskey}>Register Passkey</button>
      <button onClick={signMessage}>Sign Message</button>
      <button
        onClick={() =>
          verifySignature(
            'hello',
            '304402206455a7d11fccff6acc9fa796d3859e392ea5e53ff0f87ac355af0fa243609c8002200d0f39c7ed9701976104c89e1e4db0cdea6f7550f113d97bab1cce66f606b2b3',
            '04f309e1a88a90c5e05c521e06840e291bdd7e68a09165bce298448e19fb7b596ec0842bd17dba4eaf641125ea48896ef477c9f505fc76040396ecaa5cbe80b79b',
          )
        }>
        Verify Signature
      </button>
    </div>
  )
}
