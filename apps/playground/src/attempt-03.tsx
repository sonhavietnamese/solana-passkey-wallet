import React, { useState } from 'react'
import { startAuthentication } from '@simplewebauthn/browser'

type COSEPublicKey = {
  1: number // kty
  3: number // alg
  [-1]: Uint8Array // x coordinate
  [-2]: Uint8Array // y coordinate
}

export default function Attempt03() {
  const [status, setStatus] = useState<string>('')
  const [verificationResult, setVerificationResult] = useState<string>('')

  const coseToCompressedSEC1 = (coseKey: COSEPublicKey): Uint8Array => {
    const x = coseKey[-1]
    const y = coseKey[-2]

    // For P-256, compressed format starts with 0x02 or 0x03 depending on y being even/odd
    const prefix = new Uint8Array(1)
    prefix[0] = y[y.length - 1] & 1 ? 0x03 : 0x02

    // Concatenate prefix and x-coordinate
    const compressed = new Uint8Array(33)
    compressed.set(prefix)
    compressed.set(x, 1)

    return compressed
  }

  const p1363ToDER = (p1363Sig: Uint8Array): Uint8Array => {
    const r = p1363Sig.slice(0, 32)
    const s = p1363Sig.slice(32, 64)

    const encodeInt = (buffer: Uint8Array): Uint8Array => {
      let offset = 0
      while (offset < buffer.length && buffer[offset] === 0) offset++

      const body = buffer.slice(offset)
      const size = body.length + (body[0] & 0x80 ? 1 : 0)

      const encoded = new Uint8Array(2 + size)
      encoded[0] = 0x02 // INTEGER tag
      encoded[1] = size

      if (body[0] & 0x80) {
        encoded[2] = 0x00
        encoded.set(body, 3)
      } else {
        encoded.set(body, 2)
      }

      return encoded
    }

    const rEncoded = encodeInt(r)
    const sEncoded = encodeInt(s)

    const sequence = new Uint8Array(2 + rEncoded.length + sEncoded.length)
    sequence[0] = 0x30 // SEQUENCE tag
    sequence[1] = rEncoded.length + sEncoded.length
    sequence.set(rEncoded, 2)
    sequence.set(sEncoded, 2 + rEncoded.length)

    return sequence
  }

  const handleAuthentication = async () => {
    try {
      setStatus('Starting authentication...')

      // This would typically come from your server
      const options = {
        challenge: new Uint8Array(32),
        allowCredentials: [],
        timeout: 60000,
        userVerification: 'preferred' as const,
        rpId: window.location.hostname,
      }

      const authResult = await startAuthentication({ optionsJSON: options })

      // Convert formats
      const publicKey = authResult.response.publicKey as unknown as COSEPublicKey
      console.log('publicKey: ', publicKey)
      const signature = new Uint8Array(authResult.response.signature)

      const compressedKey = coseToCompressedSEC1(publicKey)
      const derSignature = p1363ToDER(signature)

      // Convert to hex for display
      const compressedKeyHex = Array.from(compressedKey)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')

      const derSignatureHex = Array.from(derSignature)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')

      setVerificationResult(`Compressed Public Key (33 bytes):\n${compressedKeyHex}\n\n` + `DER Signature:\n${derSignatureHex}`)

      setStatus('Conversion completed')
    } catch (error) {
      setStatus(`Error: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  return (
    <div className='p-6 max-w-2xl mx-auto'>
      <h2 className='text-2xl font-bold mb-4'>WebAuthn Format Converter</h2>

      <button
        onClick={handleAuthentication}
        className='flex items-center gap-2 bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 transition-colors'>
        Start Authentication
      </button>

      {status && (
        <div className='mt-4 p-4 bg-gray-100 rounded'>
          <p className='font-semibold'>Status:</p>
          <p>{status}</p>
        </div>
      )}

      {verificationResult && (
        <div className='mt-4 p-4 bg-gray-100 rounded'>
          <p className='font-semibold mb-2'>Converted Formats:</p>
          <pre className='whitespace-pre-wrap break-all text-sm'>{verificationResult}</pre>
        </div>
      )}
    </div>
  )
}
