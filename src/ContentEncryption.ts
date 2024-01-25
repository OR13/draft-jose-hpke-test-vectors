
import crypto from 'crypto'

import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

const suite = new CipherSuite({
  kem: KemId.DhkemP256HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes128Gcm,
});
const hkdfSha256 = suite.kdf;


export const generateContentEncryptionKey = async (enc: string) => {

  let contentEncryptionKey = undefined

  if (enc == 'A128GCM') {
    contentEncryptionKey = crypto.randomBytes(16) // possibly wrong
  }

  if (contentEncryptionKey) {
    // https://datatracker.ietf.org/doc/draft-housley-lamps-cms-cek-hkdf-sha256/
    // probably not the right salt for JOSE... 
    // but note that because ikm is generated randomly above...
    // this does nothing useful here...
    const salt = new TextEncoder().encode("The Cryptographic Message Syntax")
    const ikm = new Uint8Array(contentEncryptionKey)
    return new Uint8Array(await hkdfSha256.extract(salt, ikm))
  } else {
    throw new Error('Unsupported content encryption algorithm')
  }
}

export const encryptContent = async (
  enc: string,
  plaintext: Uint8Array,
  initializationVector: Uint8Array,
  additionalData: Uint8Array | undefined,
  contentEncryptionKey: Uint8Array
) => {
  if (enc !== 'A128GCM') {
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

export const decryptContent = async (enc: string,
  ciphertext: Uint8Array,
  initializationVector: Uint8Array,
  additionalData: Uint8Array | undefined,
  contentEncryptionKey: Uint8Array
) => {
  if (enc !== 'A128GCM') {
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
