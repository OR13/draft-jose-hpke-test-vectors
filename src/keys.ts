
import crypto from 'crypto';

import { generateKeyPair, exportJWK, calculateJwkThumbprintUri } from "jose"

import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

export type JOSE_HPKE_ALG = `HPKE-Base-P256-SHA256-AES128GCM` | `HPKE-Base-P384-SHA256-AES128GCM`

export type JWK = {
  kid?:string
  alg?: string
  kty: string
}

export type JWKS = {
  keys: JWK[]
}

export type HPKERecipient = {
  kid?: string
  encapsulated_key: string,
  encrypted_key: string
}


export const suites = {
  ['HPKE-Base-P256-SHA256-AES128GCM']: new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  }),
  ['HPKE-Base-P384-SHA256-AES128GCM']: new CipherSuite({
    kem: KemId.DhkemP384HkdfSha384,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  })
}

// // HPKE-Base-P256-SHA256-AES128GCM -> A128GCM
// const algToEnc = (alg: string) => {
//   const aead = `${alg.split('-').pop()}`;
//   if (aead === 'AES128GCM'){
//     return 'A128GCM'
//   }
// }

export const isKeyAlgorithmSupported = (recipient: JWK) => {
  const supported_alg = Object.keys(suites) as string []
  return supported_alg.includes(`${recipient.alg}`)
}

const formatJWK = (jwk: any) => {
  const { kid, alg, kty, crv, x, y, d } = jwk
  return {
    kid, alg, kty, crv, x, y, d
  }
}

export const publicFromPrivate = (privateKeyJwk: any) => { 
  const { kid, alg, kty, crv, x, y, ...rest } = privateKeyJwk
  return {
    kid, alg, kty, crv, x, y
  }
}

export const publicKeyFromJwk = async (publicKeyJwk: any) => {
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicKeyJwk,
    {
      name: 'ECDH',
      namedCurve: publicKeyJwk.crv,
    },
    true,
    [],
  )
  return publicKey;
}

export const privateKeyFromJwk = async (privateKeyJwk: any)=>{
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    privateKeyJwk,
    {
      name: 'ECDH',
      namedCurve: privateKeyJwk.crv,
    },
    true,
    ['deriveBits'],
  )
  return privateKey
}

export const generate = async (alg: JOSE_HPKE_ALG) => {
  if (!suites[alg]){
    throw new Error('Algorithm not supported')
  }
  let kp;
  if (alg.includes('P256')){
    kp = await generateKeyPair('ECDH-ES+A256KW', { crv: 'P-256', extractable: true })
  } else if (alg.includes('P384')){
    kp = await generateKeyPair('ECDH-ES+A256KW', { crv: 'P-384', extractable: true })
  } else {
    throw new Error('Could not generate private key for ' + alg)
  }
  const privateKeyJwk = await exportJWK(kp.privateKey);
  privateKeyJwk.kid = await calculateJwkThumbprintUri(privateKeyJwk)
  privateKeyJwk.alg = alg;
  return formatJWK(privateKeyJwk)
}