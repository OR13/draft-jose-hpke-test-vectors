import crypto from 'crypto';
import { base64url } from "jose";

import { publicKeyFromJwk, privateKeyFromJwk, HPKERecipient, isKeyAlgorithmSupported, suites, JOSE_HPKE_ALG, JWKS } from "./keys";

import * as ContentEncryption from './ContentEncryption'

import * as mixed from './mixed'

import * as jose from 'jose'

export type RequestGeneralEncrypt = {
  protectedHeader: { enc: 'A128GCM' }
  plaintext: Uint8Array
  additionalAuthenticatedData?: Uint8Array
  recipients: JWKS
}

export const encrypt = async (
  req: RequestGeneralEncrypt
): Promise<any> => {

  // prepare the encrypted content for all recipients
  let jwe = {} as any;

  // generate a content encryption key for a content encryption algorithm
  const contentEncryptionKey = await ContentEncryption.generateContentEncryptionKey(req.protectedHeader.enc);

  // generate an initialization vector for use with the content encryption key
  const initializationVector = crypto.getRandomValues(new Uint8Array(12)); // possibly wrong
  const iv = base64url.encode(initializationVector)

  // create the protected header
  // top level protected header only has "enc"
  const protectedHeader = base64url.encode(JSON.stringify(req.protectedHeader))

  // encrypt the plaintext with the content encryption algorithm
  const ciphertext = base64url.encode(await ContentEncryption.encryptContent(
    req.protectedHeader.enc,
    req.plaintext,
    initializationVector,
    req.additionalAuthenticatedData,
    contentEncryptionKey
  ))
  jwe.ciphertext = ciphertext;
  jwe.iv = iv;

  // for each recipient public key, encrypt the content encryption key to the recipient public key
  // and add the result to the unprotected header recipients property
  const unprotectedHeader = {
    recipients: [] as HPKERecipient[]
  }

  for (const recipient of req.recipients.keys) {
    if (isKeyAlgorithmSupported(recipient)) {
      const suite = suites[recipient.alg as JOSE_HPKE_ALG]
      // prepare the hpke sender
      const sender = await suite.createSenderContext({
        recipientPublicKey: await publicKeyFromJwk(recipient),
      });

      // encode the encapsulated key for the recipient
      const encapsulatedKey = base64url.encode(new Uint8Array(sender.enc))

      // prepare the add for the seal operation for the recipient
      // ensure the recipient must process the protected header
      // and understand the chosen "encyption algorithm"
      const hpkeSealAad = new TextEncoder().encode(protectedHeader)

      // encrypt the content encryption key to the recipient, 
      // while binding the content encryption algorithm to the protected header
      const encrypted_key = base64url.encode(new Uint8Array(await sender.seal(contentEncryptionKey, hpkeSealAad)));

      unprotectedHeader.recipients.push(
        {
          kid: recipient.kid,
          encapsulated_key: encapsulatedKey,
          encrypted_key: encrypted_key
        }
      )
    } else if (recipient.alg === 'ECDH-ES+A128KW') {
      // throw new Error('Mixed mode not supported')
      const ek = await jose.generateKeyPair(recipient.alg, { crv: recipient.crv, extractable: true })
      const epk = await jose.exportJWK(ek.publicKey)
      const sharedSecret = await mixed.deriveKey( recipient, await jose.exportJWK(ek.privateKey))
      const encrypted_key = mixed.wrap('A128KW', sharedSecret, contentEncryptionKey)
      unprotectedHeader.recipients.push({
        encrypted_key: base64url.encode(encrypted_key),
        header: {
          alg: recipient.alg,
          epk: epk
        }
      } as any)

    } else {
      throw new Error('Public key algorithm not supported: ' + recipient.alg)
    }

  }
  jwe.recipients = unprotectedHeader.recipients

  if (req.additionalAuthenticatedData) {
    jwe.aad = base64url.encode(req.additionalAuthenticatedData)
  }

  jwe.protected = protectedHeader
  return jwe;
}

export type RequestGeneralDecrypt = {
  jwe: any,
  privateKeys: JWKS
}


const produceDecryptionResult = async (parsedProtectedHeader: any, ciphertext: string, aad: string, iv: string, cek: Uint8Array) => {
  let contentEncryptionAad = undefined;
  if (aad) {
    contentEncryptionAad = base64url.decode(aad)
  }
  const ct = base64url.decode(ciphertext)
  const initializationVector = base64url.decode(iv);
  const plaintext = await ContentEncryption.decryptContent(parsedProtectedHeader.enc, ct, initializationVector, contentEncryptionAad, cek)
  const decryption = { plaintext: new Uint8Array(plaintext) } as any;
  decryption.protectedHeader = parsedProtectedHeader;
  decryption.aad = contentEncryptionAad;
  return decryption
}

export const decrypt = async (req: RequestGeneralDecrypt): Promise<any> => {
  const { protected: protectedHeader, recipients, iv, ciphertext, aad } = req.jwe;
  const parsedProtectedHeader = JSON.parse(new TextDecoder().decode(base64url.decode(protectedHeader)));

  // find a recipient for which we have a private key
  let matchingRecipient = undefined
  let matchingPrivateKey = undefined
  for (const privateKey of req.privateKeys.keys) {
    const recipient = recipients.find((r: HPKERecipient) => {
      return r.kid === privateKey.kid
    })
    if (recipient) {
      // we have a private key for this recipient
      matchingRecipient = recipient;
      matchingPrivateKey = privateKey;
      break
    }
  }

  if (!matchingRecipient || !matchingPrivateKey) {
    throw new Error('No decryption key found for the given recipients')
  }

  if (isKeyAlgorithmSupported(matchingPrivateKey)) {
    // We could check here to see if the "enc" in the protected header
    // matches the last part of the "alg" on the private key.

    const suite = suites[matchingPrivateKey.alg as JOSE_HPKE_ALG]

    // selected the encapsulated_key for the recipient
    const { encapsulated_key, encrypted_key } = matchingRecipient;

    // create the HPKE recipient
    const recipient = await suite.createRecipientContext({
      recipientKey: await privateKeyFromJwk(matchingPrivateKey),
      enc: base64url.decode(encapsulated_key)
    })

    // compute the additional data from the protected header
    // this will be used to protect against 
    // a cross mode attack on the aead
    const hpkeOpenAad = new TextEncoder().encode(protectedHeader)

    // open the content encryption key for the given content encryption algorithm
    // which is described in the protected header
    const contentEncryptionKey = new Uint8Array(await recipient.open(base64url.decode(encrypted_key), hpkeOpenAad))

    // determine the content encryption algorithm
    // now that we know we have a key that supports it
    return produceDecryptionResult(parsedProtectedHeader, ciphertext, aad, iv, contentEncryptionKey);
  } else if (matchingPrivateKey.alg === 'ECDH-ES+A128KW') {
    // compute the shared secret from the recipient
    const sharedSecret = await mixed.deriveKey( matchingRecipient.header.epk, matchingPrivateKey)
    const encryptedKey = jose.base64url.decode(matchingRecipient.encrypted_key)
    // unrwap the content encryption key
    const contentEncryptionKey = mixed.unwrap('A128KW', sharedSecret, encryptedKey)
    // the test is the same for both HPKE-Base-P256-SHA256-AES128GCM and ECDH-ES+A128KW with A128GCM
    return produceDecryptionResult(parsedProtectedHeader, ciphertext, aad, iv, contentEncryptionKey);
  } else {
    throw new Error('Private key algorithm not supported.')
  }

}