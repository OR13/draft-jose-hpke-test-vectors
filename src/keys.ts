
import crypto from 'crypto';

import { generateKeyPair, exportJWK, calculateJwkThumbprintUri } from "jose"

export type DEFAULT_ALG = 'HPKE-Base-P256-SHA256-AES128GCM'

export const default_alg: DEFAULT_ALG = 'HPKE-Base-P256-SHA256-AES128GCM'


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

export const generate = async (alg: DEFAULT_ALG) => {
  const { privateKey } = await generateKeyPair('ECDH-ES+A256KW', { crv: 'P-256', extractable: true })
  const privateKeyJwk = await exportJWK(privateKey);
  privateKeyJwk.kid = await calculateJwkThumbprintUri(privateKeyJwk)
  privateKeyJwk.alg = default_alg;
  return formatJWK(privateKeyJwk)
}