import { base64url } from "jose";


import { publicKeyFromJwk, suites, isKeyAlgorithmSupported, privateKeyFromJwk, JOSE_HPKE_ALG } from "./keys";


export const encrypt = async (plaintext: Uint8Array, publicKeyJwk: any): Promise<string> => {
  if ( ! isKeyAlgorithmSupported(publicKeyJwk)){
    throw new Error('Public key algorithm is not supported')
  }
  const suite = suites[publicKeyJwk.alg as JOSE_HPKE_ALG]
  const sender = await suite.createSenderContext({
    recipientPublicKey: await publicKeyFromJwk(publicKeyJwk),
  });
  const protectedHeader = base64url.encode(JSON.stringify({ alg: publicKeyJwk.alg }))
  const encapsulatedKey = base64url.encode(new Uint8Array(sender.enc))
  const ciphertext = base64url.encode(new Uint8Array(await sender.seal(plaintext, new TextEncoder().encode(protectedHeader))));
  // https://datatracker.ietf.org/doc/html/rfc7516#section-3.1
  return `${protectedHeader}.${encapsulatedKey}..${ciphertext}.`

}

export const decrypt = async (compact: string, privateKeyJwk: any): Promise<Uint8Array> => {
  if ( ! isKeyAlgorithmSupported(privateKeyJwk)){
    throw new Error('Public key algorithm is not supported')
  }
  const suite = suites[privateKeyJwk.alg as JOSE_HPKE_ALG]
  const [protectedHeader, encapsulatedKey, _blankIv, ciphertext, _blankTag] = compact.split('.');
  const recipient = await suite.createRecipientContext({
    recipientKey: await privateKeyFromJwk(privateKeyJwk),
    enc: base64url.decode(encapsulatedKey)
  })
  const plaintext = await recipient.open(base64url.decode(ciphertext), new TextEncoder().encode(protectedHeader))
  return new Uint8Array(plaintext)
}