import crypto from 'crypto';
import { base64url } from "jose";

import { publicKeyFromJwk, privateKeyFromJwk, HPKERecipient, isKeyAlgorithmSupported, suites, JOSE_HPKE_ALG, JWK, JWKS } from "./keys";

import * as ContentEncryption from './ContentEncryption'

export const encrypt = async (
  enc: string,
  plaintext: Uint8Array,
  recipients: JWKS
): Promise<any> => {

  // prepare the encrypted content for all recipients

  // generate a content encryption key for a content encryption algorithm
  const contentEncryptionKey = await ContentEncryption.generateContentEncryptionKey(enc);

  // generate an initialization vector for use with the content encryption key
  const initializationVector = crypto.getRandomValues(new Uint8Array(12)); // possibly wrong
  const iv = base64url.encode(initializationVector)

  // create the protected header
  // top level protected header only has "enc"
  const protectedHeader = base64url.encode(JSON.stringify({ enc }))

  // encrypt the plaintext with the content encryption algorithm
  const contentEncryptionAad = undefined
  const ciphertext = base64url.encode(await ContentEncryption.encryptContent(enc, plaintext, initializationVector, contentEncryptionAad, contentEncryptionKey))

  // for each recipient public key, encrypt the content encryption key to the recipient public key
  // and add the result to the unprotected header recipients property
  const unprotectedHeader = {
    recipients: [] as HPKERecipient[]
  }

  for (const recipient of recipients.keys) {
    if (!isKeyAlgorithmSupported(recipient)) {
      throw new Error('Public key algorithm not supported.')
    }
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
  }

  // https://datatracker.ietf.org/doc/html/rfc7516#section-3.2
  return {
    protected: protectedHeader,
    unprotected: unprotectedHeader,
    iv,
    ciphertext,
  }
}

export const decrypt = async (json: any, recipients: JWKS): Promise<any> => {
  const { protected: protectedHeader, unprotected, iv, ciphertext } = json;

  // find a recipient for which we have a private key
  let matchingRecipient = undefined
  let matchingPrivateKey = undefined
  for (const privateKey of recipients.keys){
    const recipient = unprotected.recipients.find((r: HPKERecipient)=>{
      return r.kid === privateKey.kid
    })
    if (recipient){
      // we have a private key for this recipient
      matchingRecipient = recipient;
      matchingPrivateKey = privateKey;
      break
    }
  } 

  if (!matchingRecipient || !matchingPrivateKey){
    throw new Error('No decryption key found for the given recipients')
  }

  if (!isKeyAlgorithmSupported(matchingPrivateKey)){
    throw new Error('Private key algorithm not supported.')
  }
  // We could check here to see if the "enc" in the protected header
  // matches the last part of the "alg" on the private key.
  

  const suite = suites[matchingPrivateKey.alg as JOSE_HPKE_ALG]
  
  // TODO: mixed recipients support goes here... (ECDH-ES and HPKE)

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
  const additionalData = new TextEncoder().encode(protectedHeader)

  // open the content encryption key for the given content encryption algorithm
  // which is described in the protected header
  const decryptedContentEncryptionKey = await recipient.open(base64url.decode(encrypted_key), additionalData)

  // determine the content encryption algorithm
  // now that we know we have a key that supports it
  const { enc } = JSON.parse(new TextDecoder().decode(base64url.decode(protectedHeader)));

  // decrypt the ciphertext
  const ct = base64url.decode(ciphertext)
  const initializationVector = base64url.decode(iv);
  const contentEncryptionKey = new Uint8Array(decryptedContentEncryptionKey)
  const contentEncryptionAad = undefined;
  const plaintext = await ContentEncryption.decryptContent(enc, ct, initializationVector, contentEncryptionAad, contentEncryptionKey)
  return new Uint8Array(plaintext)
}