import { base64url } from "jose";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

import { publicKeyFromJwk, default_alg, privateKeyFromJwk } from "./keys";

const defaultSuite = new CipherSuite({
  kem: KemId.DhkemP256HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes128Gcm,
});

export const encrypt = async (plaintext: Uint8Array, publicKeyJwk: any): Promise<string> => {
  if (publicKeyJwk.alg !== default_alg){
    throw new Error('Public key is not for: ' + default_alg)
  }
  const sender = await defaultSuite.createSenderContext({
    recipientPublicKey: await publicKeyFromJwk(publicKeyJwk),
  });
  const protectedHeader = base64url.encode(JSON.stringify({ alg: publicKeyJwk.alg }))
  const encapsulatedKey = base64url.encode(new Uint8Array(sender.enc))
  const ciphertext = base64url.encode(new Uint8Array(await sender.seal(plaintext, new TextEncoder().encode(protectedHeader))));
  // https://datatracker.ietf.org/doc/html/rfc7516#section-3.1
  return `${protectedHeader}.${encapsulatedKey}..${ciphertext}.`

}

export const decrypt = async (compact: string, privateKeyJwk: any): Promise<Uint8Array> => {
  if (privateKeyJwk.alg !== default_alg){
    throw new Error('Public key is not for: ' + default_alg)
  }
  const [protectedHeader, encapsulatedKey, _blankIv, ciphertext, _blankTag] = compact.split('.');
  const recipient = await defaultSuite.createRecipientContext({
    recipientKey: await privateKeyFromJwk(privateKeyJwk), // rkp (CryptoKeyPair) is also acceptable.
    enc: base64url.decode(encapsulatedKey)
  })
  const plaintext = await recipient.open(base64url.decode(ciphertext), new TextEncoder().encode(protectedHeader))
  return new Uint8Array(plaintext)
}