
import crypto from 'crypto'

export const generateContentEncryptionKey = (enc: string) => {
  if (enc == 'A128GCM') {
    const contentEncryptionKey = crypto.randomBytes(16) // possibly wrong
    return contentEncryptionKey;
  }
  throw new Error('Unsupported content encryption algorithm')
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
