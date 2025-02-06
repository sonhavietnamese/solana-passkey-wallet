import { useState, useEffect } from 'react'
import { client, server } from '@passwordless-id/webauthn'

import { isBase64url, toBase64url, toBuffer, bufferToHex } from '@passwordless-id/webauthn/dist/esm/utils'

const DEFAULT_USERNAME = 'test-pk'

const MESSAGE = 'hello'

export default function App() {
  const [storedPasskeys, setStoredPasskeys] = useState<Array<{ id: string; username: string; selected: boolean; publicKey: string }>>([])
  const [selectedPasskeyId, setSelectedPasskeyId] = useState<string | null>(null)

  // Load stored passkeys on component mount
  useEffect(() => {
    const stored = localStorage.getItem('passkeys')
    if (stored) {
      setStoredPasskeys(JSON.parse(stored))
    }
  }, [])

  const register = async (username: string) => {
    // try {
    const challenge = server.randomChallenge()
    const name = username + Date.now()

    //   const registration = await client.register({
    //     user: name,
    //     challenge: challenge,
    //     userVerification: 'required',
    //     attestation: true,
    //   })

    //   console.log('Registration:', registration)

    //   // Store the new passkey
    //   const newPasskey = {
    //     id: registration.id,
    //     username: name,
    //     selected: false,
    //     publicKey: registration.response.publicKey,
    //   }

    //   console.log(registration.response.publicKey)
    //   console.log('Hex:', bufferToHex(toBuffer(registration.response.publicKey)))

    //   const updatedPasskeys = [...storedPasskeys, newPasskey]
    //   localStorage.setItem('passkeys', JSON.stringify(updatedPasskeys))
    //   setStoredPasskeys(updatedPasskeys)

    //   console.log(registration)
    // } catch (error) {
    //   console.error('Failed to register:', error)
    // }

    try {
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: new Uint8Array(32),
          rp: {
            name: 'Your App Name',
            id: window.location.hostname,
          },
          user: {
            id: new Uint8Array(32),
            name: name,
            displayName: name,
          },
          pubKeyCredParams: [{ alg: -7, type: 'public-key' }],

          attestationFormats: ['packed'],
        },
      })

      console.log('Credential:', credential)

      const publicKey = credential?.response?.getPublicKey()
      console.log('Public key:', publicKey)
    } catch (error) {
      console.error('Error creating passkey:', error)
    }
  }

  const signMessage = async () => {
    if (!selectedPasskeyId) {
      console.error('No passkey selected')
      return
    }

    try {
      const message = MESSAGE

      // const challenge = server.randomChallenge()

      // console.log('Challenge:', challenge)

      // Use authenticate to sign the message with the passkey
      const signature = await client.authenticate({
        challenge: message,
        allowCredentials: [
          {
            id: selectedPasskeyId,
            transports: ['internal', 'hybrid'],
          },
        ],
        userVerification: 'required',
      })

      console.log('Signature:', signature)

      console.log('Message:', message)
      console.log('Signature:', signature.response.signature)
      // console.log('Public key:', signature.response.)
      const messageBuffer = toBuffer(message)
      console.log('Message buffer:', messageBuffer)
      console.log('Message array:', Array.from(new Uint8Array(messageBuffer)))
      const signatureBuffer = toBuffer(signature.response.signature)
      console.log('Signature buffer:', signatureBuffer)
      console.log('Signature array:', Array.from(new Uint8Array(signatureBuffer)))

      return signature
    } catch (error) {
      console.error('Failed to sign message:', error)
    }
  }

  const signMessageRaw = async () => {
    try {
      const signature = await navigator.credentials.get({
        publicKey: {
          challenge: new TextEncoder().encode(MESSAGE),
        },
      })

      console.log('Message Hex:', bufferToHex(toBuffer(MESSAGE)))

      console.log('Signature:', signature.response.signature)
      console.log('Base64:', toBase64url(signature.response.signature))
      console.log('Signature:', bufferToHex(signature.response.signature))
    } catch (error) {
      console.error('Failed to sign message:', error)
    }
  }

  const selectPasskey = (passkeyId: string) => {
    setSelectedPasskeyId(passkeyId)
    const updatedPasskeys = storedPasskeys.map((passkey) => ({
      ...passkey,
      selected: passkey.id === passkeyId,
    }))
    localStorage.setItem('passkeys', JSON.stringify(updatedPasskeys))
    setStoredPasskeys(updatedPasskeys)
  }

  const convertPublicKey = (publicKey: string) => {
    const publicKeyBuffer = toBuffer(publicKey)
    const publicKeyArray = Array.from(new Uint8Array(publicKeyBuffer))

    // copy public key array to clipboard
    navigator.clipboard.writeText(publicKeyArray.join(','))

    console.log('Public key array:', publicKeyArray)
  }

  return (
    <main className='w-dvw min-h-dvh flex flex-col items-center justify-center gap-4'>
      <button className='bg-blue-500 text-white p-2 rounded-md' onClick={() => register(DEFAULT_USERNAME)}>
        Sign in
      </button>
      <button
        className='bg-blue-500 text-white p-2 rounded-md'
        onClick={() => {
          console.log(
            isBase64url('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEajPuA48ozmgnbnVTUa5JQBI_KVyJ2YIS06pK6QJbgTy9I9fbbyB0r8myZibt08rKUdAJ3O6D9kvQbV5jIkVLmQ'),
          )
        }}>
        Check Passkey
      </button>
      <button className='bg-blue-500 text-white p-2 rounded-md' onClick={() => signMessage()}>
        Sign Message
      </button>

      <button className='bg-blue-500 text-white p-2 rounded-md' onClick={() => signMessageRaw()}>
        Sign Message Raw
      </button>
      <button
        className='bg-blue-500 text-white p-2 rounded-md'
        onClick={() =>
          convertPublicKey(
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj8i_soAaWmhTv-tFBw5ED_oo6E0LgO4AXhBzBUpMduKwRUOJoEiUVYrnC8pEkM0PeAAmVtfpOAdIURjagtdgAQ==',
          )
        }></button>
      {/* Passkeys Table */}
      {storedPasskeys.length > 0 && (
        <div className='w-full max-w-2xl mt-8'>
          <h2 className='text-xl font-bold mb-4'>Stored Passkeys</h2>
          <table className='w-full border-collapse border border-gray-300'>
            <thead>
              <tr className='bg-gray-100'>
                <th className='border border-gray-300 p-2'>Username</th>
                <th className='border border-gray-300 p-2'>Public Key</th>
                <th className='border border-gray-300 p-2'>Passkey ID</th>
                <th className='border border-gray-300 p-2'>Action</th>
              </tr>
            </thead>
            <tbody>
              {storedPasskeys.map((passkey) => (
                <tr key={passkey.id} className={passkey.id === selectedPasskeyId ? 'bg-blue-100' : ''}>
                  <td className='border border-gray-300 p-2' style={{ backgroundColor: passkey.id === selectedPasskeyId ? 'blue' : 'white' }}>
                    {passkey.username}
                  </td>
                  <td className='border border-gray-300 p-2'>{passkey.publicKey || 'N/A'}</td>
                  <td className='border border-gray-300 p-2'>{passkey.id}</td>
                  <td className='border border-gray-300 p-2'>
                    <button
                      className={`${passkey.id === selectedPasskeyId ? 'bg-blue-600' : 'bg-green-500'} text-white p-1 rounded-md`}
                      onClick={() => selectPasskey(passkey.id)}>
                      {passkey.id === selectedPasskeyId ? 'Selected' : 'Use This Passkey'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  )
}
