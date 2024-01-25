import crypto from 'crypto';
import { base64url } from "jose";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

import { publicKeyFromJwk, default_alg, privateKeyFromJwk } from "./keys";

const defaultSuite = new CipherSuite({
  kem: KemId.DhkemP256HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes128Gcm,
});

const encryptContent = async (enc: string, plaintext: Uint8Array, initializationVector:Uint8Array, additionalData: Uint8Array | undefined, contentEncryptionKey: Uint8Array) => {
  if (enc !== 'AES128GCM'){
    throw new Error('encryption algorithm not supported.')
  }
  const key = await crypto.subtle.importKey('raw', contentEncryptionKey, {
    name: "AES-GCM",
  }, true, ["encrypt", "decrypt"])
  const encrypted_content = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: initializationVector, additionalData },
    key,
    plaintext,
  );
  return new Uint8Array(encrypted_content)
}

const decryptContent = async (enc: string, ciphertext: Uint8Array, initializationVector:Uint8Array, additionalData: Uint8Array| undefined, contentEncryptionKey: Uint8Array) => {
  if (enc !== 'AES128GCM'){
    throw new Error('encryption algorithm not supported.')
  }
  const key = await crypto.subtle.importKey('raw', contentEncryptionKey, {
    name: "AES-GCM",
  }, true, ["encrypt", "decrypt"])
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: initializationVector, additionalData },
    key,
    ciphertext,
  );
  return new Uint8Array(plaintext)
}

export const encrypt = async (plaintext: Uint8Array, publicKeyJwk: any): Promise<any> => {
  if (publicKeyJwk.alg !== default_alg){
    throw new Error('Public key is not for: ' + default_alg)
  }
  const sender = await defaultSuite.createSenderContext({
    recipientPublicKey: await publicKeyFromJwk(publicKeyJwk),
  });
  const protectedHeader = base64url.encode(JSON.stringify({ alg: publicKeyJwk.alg  }))
  // {
  //   "alg": "HPKE-Base-P256-SHA256-AES128GCM"
  // }
  const encapsulatedKey = base64url.encode(new Uint8Array(sender.enc))
  const contentEncryptionKey = crypto.randomBytes(16) // possibly wrong
  // at this point we have a content encryption key generated and we know it is for use with "AES128GCM"
  // we will include the protectected header as aad in seal, to improve the probability that consumers
  // use the correct aead that the sender intended the receive to use to decrypt.
  const initializationVector = crypto.getRandomValues(new Uint8Array(12)); // possibly wrong
  const additionalData = new TextEncoder().encode(protectedHeader)
  const encrypted_key = base64url.encode(new Uint8Array(await sender.seal(contentEncryptionKey, additionalData)));
  // seal is applied to a key, with a known encryption algorithm
  // the binding is preserved by the aad on seal.
  // https://datatracker.ietf.org/doc/html/rfc7516#section-3.2
  const contentEncryptionAad = undefined;
  const ciphertext = base64url.encode(await encryptContent("AES128GCM", plaintext, initializationVector, contentEncryptionAad, contentEncryptionKey))
  return {
    protected: protectedHeader,
    unprotected: {
      recipients: [
        {
          kid: publicKeyJwk.kid,
          encapsulated_key: encapsulatedKey,
          encrypted_key: encrypted_key
        }
      ]
    },
    iv: base64url.encode(initializationVector),
    ciphertext,
  }
}

export const decrypt = async (json: any, privateKeyJwk: any): Promise<any> => {
  if (privateKeyJwk.alg !== default_alg){
    throw new Error('Public key is not for: ' + default_alg)
  }
  const { protected: protectedHeader, unprotected, iv, ciphertext} = json;
  const ct = base64url.decode(ciphertext)
  const additionalData = new TextEncoder().encode(protectedHeader)
  const initializationVector = base64url.decode(iv);
  const {recipients: [{ encapsulated_key, encrypted_key }]} = unprotected
  const recipient = await defaultSuite.createRecipientContext({
    recipientKey: await privateKeyFromJwk(privateKeyJwk),
    enc: base64url.decode(encapsulated_key)
  })
  const decryptedContentEncryptionKey = await recipient.open(base64url.decode(encrypted_key), additionalData)
  // open takes the protected header as aad
  // open fails if the protected header algorithm is changed
  // we can then use the enc value from "alg" safely.
  const header = JSON.parse(new TextDecoder().decode(base64url.decode(protectedHeader)));
  const enc = header.alg.split('-').pop(); // expect AES128GCM
  const contentEncryptionAad = undefined;
  const contentEncryptionKey = new Uint8Array(decryptedContentEncryptionKey)
  const plaintext = await decryptContent(enc, ct, initializationVector, contentEncryptionAad, contentEncryptionKey)
  return new Uint8Array(plaintext)
}