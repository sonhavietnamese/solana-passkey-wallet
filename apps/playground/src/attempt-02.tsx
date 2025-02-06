import { startAuthentication, startRegistration } from '@simplewebauthn/browser'
import { generateAuthenticationOptions, generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server'
import { decodeCredentialPublicKey } from '@simplewebauthn/server/helpers'
import ConvertPasskeyFormat from './convert-passkey-format'

const MESSAGE = 'hello'

export default function Attempt02() {
  const registerPasskey = async () => {
    const username = 's' + Date.now()
    const userID = new Uint8Array(username.split('').map((char) => char.charCodeAt(0)))

    const registrationOptions = await generateRegistrationOptions({
      challenge: 'register-passkey',
      rpName: 'simplewebauthn',
      rpID: 'localhost',
      userName: username,
      userID,
      attestationType: 'none',
    })

    console.log('registrationOptions: ', registrationOptions)
    let attResp
    try {
      // Pass the options to the authenticator and wait for a response
      attResp = await startRegistration({ optionsJSON: registrationOptions })
      console.log('Public Key: ', attResp.response.publicKey?.toString())
      console.log('Attestation Object: ', attResp)

      console.log('Verify registration')
      let verification

      verification = await verifyRegistrationResponse({
        response: attResp,
        expectedChallenge: registrationOptions.challenge,
        expectedOrigin: 'http://localhost:5173',
        expectedRPID: 'localhost',
      })

      const { verified } = verification
      console.log('verified: ', verified)

      console.log('Convert public key to hex')
      const publicKeyBase64Url = attResp.response.publicKey?.toString()
      const base64 = publicKeyBase64Url.replace(/-/g, '+').replace(/_/g, '/')

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
      // Some basic error handling
      if (error.name === 'InvalidStateError') {
        console.log('Error: Authenticator was probably already registered by user')
      } else {
        console.log('Error: ', error)
      }

      throw error
    }
  }

  // known for authentication
  const signMessage = async () => {
    const options = await generateAuthenticationOptions({
      rpID: 'localhost',
      challenge: MESSAGE,
      // allowCredentials: [
      //   {
      //     id: 'czE3Mzg3Mzk2OTI0NDM',
      //     transports: ['internal', 'hybrid'],
      //   },
      // ],
    })

    let asseResp
    try {
      // Pass the options to the authenticator and wait for a response
      asseResp = await startAuthentication({ optionsJSON: options })
      console.log('Assertion Response: ', asseResp)
      console.log('Signature: ', asseResp.response.signature)
    } catch (error) {
      // Some basic error handling
      console.log('Error: ', error)
      throw error
    }
  }

  const testDecodePublicKey = async () => {
    const publicKeyBytes = [
      165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 170, 179, 55, 205, 105, 156, 240, 114, 178, 39, 239, 34, 156, 85, 212, 42, 168, 65, 125, 37, 179, 69, 144,
      213, 157, 28, 166, 223, 39, 160, 185, 252, 34, 88, 32, 39, 95, 210, 139, 26, 85, 59, 195, 215, 154, 15, 230, 180, 50, 165, 240, 177, 168, 210,
      146, 143, 23, 181, 64, 41, 147, 155, 163, 44, 5, 179, 15,
    ]
    const publicKey = new Uint8Array(publicKeyBytes)
    const decoded = decodeCredentialPublicKey(publicKey)
    console.log('decoded: ', decoded)
  }

  return (
    <div className='flex flex-col gap-4'>
      <button className='bg-blue-500 text-white p-2 rounded-md' onClick={registerPasskey}>
        Register Passkey
      </button>
      <button className='bg-blue-500 text-white p-2 rounded-md' onClick={signMessage}>
        Sign Message
      </button>

      <button onClick={() => testDecodePublicKey()}>Test decode publickey</button>

      <ConvertPasskeyFormat />
    </div>
  )
}
