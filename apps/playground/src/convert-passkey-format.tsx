import { useState } from 'react'
import {} from '@simplewebauthn/server/helpers'

type COSEPublicKey = {
  1: number // kty
  3: number // alg
  [-1]: Uint8Array // x coordinate
  [-2]: Uint8Array // y coordinate
}

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

export default function ConvertPasskeyFormat() {
  const [publicKeyBase64, setPublicKeyBase64] = useState('')
  const [signatureBase64, setSignatureBase64] = useState('')
  const [publicKeyHex, setPublicKeyHex] = useState('')
  const [signatureHex, setSignatureHex] = useState('')

  const convertPublicKeyBase64 = () => {
    if (publicKeyBase64.length === 0) return

    const base64 = publicKeyBase64.replace(/-/g, '+').replace(/_/g, '/')

    // Decode base64 string to bytes
    const binaryString = atob(base64)
    const bytes = new Uint8Array(binaryString.length)
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i)
    }

    // Find the actual key bytes by looking for the OID for P-256 (1.2.840.10045.3.1.7)
    // followed by a BIT STRING tag (0x03)
    const p256Prefix = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
    let keyStart = -1

    for (let i = 0; i < bytes.length - p256Prefix.length; i++) {
      let match = true
      for (let j = 0; j < p256Prefix.length; j++) {
        if (bytes[i + j] !== p256Prefix[j]) {
          match = false
          break
        }
      }
      if (match && bytes[i + p256Prefix.length] === 0x03) {
        keyStart = i + p256Prefix.length
        break
      }
    }

    if (keyStart === -1) {
      console.error('Could not find P-256 key data')
      return
    }

    // Skip the BIT STRING tag and length
    keyStart += 2
    // Skip the leading zero byte
    keyStart += 1

    const rawKeyBytes = bytes.slice(keyStart)
    const publicKeyHex = Array.from(rawKeyBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')

    console.log('Public Key (hex for Rust):', publicKeyHex)
    setPublicKeyHex(publicKeyHex)
  }

  const convertSignatureBase64 = () => {
    if (signatureBase64.length === 0) return

    const sigBase64 = signatureBase64.replace(/-/g, '+').replace(/_/g, '/')

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

    // Parse DER format with variable lengths
    let pos = 0

    // Sequence tag (0x30)
    if (sigBytes[pos++] !== 0x30) throw new Error('Invalid DER sequence')

    // Sequence length
    let seqLen = sigBytes[pos++]
    if (seqLen & 0x80) {
      const lenBytes = seqLen & 0x7f
      seqLen = 0
      for (let i = 0; i < lenBytes; i++) {
        seqLen = (seqLen << 8) | sigBytes[pos++]
      }
    }

    // R integer
    if (sigBytes[pos++] !== 0x02) throw new Error('Invalid R integer tag')
    let rLen = sigBytes[pos++]
    // Skip leading zero if present
    let rStart = pos
    if (sigBytes[pos] === 0x00) {
      rStart++
      rLen--
    }
    const rBytes = sigBytes.slice(rStart, rStart + rLen)
    pos += rLen + (rStart - pos)

    // S integer
    if (sigBytes[pos++] !== 0x02) throw new Error('Invalid S integer tag')
    let sLen = sigBytes[pos++]
    // Skip leading zero if present
    let sStart = pos
    if (sigBytes[sStart] === 0x00) {
      sStart++
      sLen--
    }
    const sBytes = sigBytes.slice(sStart, sStart + sLen)

    // Pad R and S to 32 bytes each
    const rPadded = new Uint8Array(32)
    const sPadded = new Uint8Array(32)
    rPadded.set(rBytes, 32 - rBytes.length)
    sPadded.set(sBytes, 32 - sBytes.length)

    // Format R and S as hex strings
    const rHex = Array.from(rPadded)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    const sHex = Array.from(sPadded)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')

    console.log('R value (hex):', rHex)
    console.log('S value (hex):', sHex)

    // Format signature for Rust code (concatenated R and S)
    const rustSignatureHex = rHex + sHex
    console.log('Signature for Rust (hex):', rustSignatureHex)
    setSignatureHex(rustSignatureHex)
  }

  return (
    <div className='flex flex-col'>
      <div className=''>
        <input type='text' className='w-full border' value={publicKeyBase64} onChange={(e) => setPublicKeyBase64(e.target.value)} />
        <button onClick={convertPublicKeyBase64}>Convert</button>
      </div>
      <div className=''>
        <input type='text' className='w-full border' value={signatureBase64} onChange={(e) => setSignatureBase64(e.target.value)} />
        <button onClick={convertSignatureBase64}>Convert</button>
      </div>
    </div>
  )
}
