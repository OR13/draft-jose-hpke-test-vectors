import crypto from 'crypto';
import { base64url } from "jose";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

import { publicKeyFromJwk, default_alg, privateKeyFromJwk } from "./keys";

const defaultSuite = new CipherSuite({
  kem: KemId.DhkemP256HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes128Gcm,
});

const encryptContent = async (plaintext: Uint8Array, initializationVector:Uint8Array, additionalData: Uint8Array, contentEncryptionKey: Uint8Array) => {
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

const decryptContent = async (ciphertext: Uint8Array, initializationVector:Uint8Array, additionalData: Uint8Array, contentEncryptionKey: Uint8Array) => {
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
  // unused.
  const protectedHeader = base64url.encode(JSON.stringify({ alg: publicKeyJwk.alg, enc: publicKeyJwk.alg.split('-').pop() /* AES128GCM */ }))
  // {
  //   "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  //   "enc": "AES128GCM"
  // }
  const encapsulatedKey = base64url.encode(new Uint8Array(sender.enc))
  const contentEncryptionKey = crypto.randomBytes(16) // possibly wrong
  const initializationVector = crypto.getRandomValues(new Uint8Array(12)); // possibly wrong
  const additionalData = new TextEncoder().encode(protectedHeader)
  const encrypted_key = base64url.encode(new Uint8Array(await sender.seal(contentEncryptionKey, additionalData)));
  // https://datatracker.ietf.org/doc/html/rfc7516#section-3.2
  const unprotected = {
    recipients: [
      {
        kid: publicKeyJwk.kid,
        encapsulated_key: encapsulatedKey,
        encrypted_key: encrypted_key
      }
    ]
  }
  const ciphertext = base64url.encode(await encryptContent(plaintext, initializationVector, additionalData, contentEncryptionKey))
  return {
    protected: protectedHeader,
    unprotected,
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
  const contentEncryptionKey = new Uint8Array(decryptedContentEncryptionKey)
  const plaintext = await decryptContent(ct, initializationVector, additionalData, contentEncryptionKey)
  return new Uint8Array(plaintext)
}