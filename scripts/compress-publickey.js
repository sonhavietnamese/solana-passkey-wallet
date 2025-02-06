var EC = require('elliptic').ec
var ec = new EC('p256')

const publicKeyArray = [
  48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 128, 243, 87, 45, 117, 217, 149, 17, 147, 49,
  189, 86, 95, 221, 28, 220, 109, 17, 224, 221, 66, 123, 26, 74, 214, 1, 133, 1, 209, 206, 121, 92, 74, 35, 225, 37, 82, 150, 181, 64, 110, 8, 50,
  190, 235, 73, 75, 198, 249, 144, 25, 212, 26, 236, 191, 119, 252, 159, 185, 96, 244, 172, 71, 36,
]

// Remove the leading 0x04 byte (point format):
// const publicKeyCoordinates = publicKeyArray.slice(26) // Start from the x-coordinate

const publicKeyHex = Buffer.from(publicKeyArray).toString('hex')
// const key = ec.keyFromPublic(publicKeyHex, 'spki') // Use 'spki' format

// console.log(key)
const pubKeyContent = publicKeyHex.slice(52) // 26 bytes * 2 hex chars per byte = 52
const key = ec.keyFromPublic(pubKeyContent, 'hex')

console.log(key.getPrivate('hex'))
// // Split into x and y coordinates (each 32 bytes):
// const x = publicKeyCoordinates.slice(0, 32)
// const y = publicKeyCoordinates.slice(32)

// const key = EC.keyFromPublic([x, y], 'array') // Pass x and y as an array
// const uncompressedKey = key.getPublic('array')
// const keyFromServer = EC.keyFromPublic(uncompressedKey, 'array')

// console.log(keyFromServer)

// For verification, you'll need the message hash and signature:
// const signatureValid = key.verify(messageHash, signature);
