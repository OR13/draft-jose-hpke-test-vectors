
import crypto from 'crypto';

import * as jose from 'jose'

import { publicKeyFromJwk, privateKeyFromJwk } from './keys';

// https://github.com/panva/jose/blob/08eff759a032585a950d79e6989dfcb373a8900e/src/lib/buffer_utils.ts#L49

import { createHash, createSecretKey, createDecipheriv, createCipheriv } from 'node:crypto'

const digest: any = (
  algorithm: 'sha256' | 'sha384' | 'sha512',
  data: Uint8Array,
): Uint8Array => createHash(algorithm).update(data).digest()

const MAX_INT32 = 2 ** 32

function writeUInt32BE(buf: Uint8Array, value: number, offset?: number) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`)
  }
  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset)
}
export function uint32be(value: number) {
  const buf = new Uint8Array(4)
  writeUInt32BE(buf, value)
  return buf
}

export async function concatKdf(secret: Uint8Array, bits: number, value: Uint8Array) {
  const iterations = Math.ceil((bits >> 3) / 32)
  const res = new Uint8Array(iterations * 32)
  for (let iter = 0; iter < iterations; iter++) {
    const buf = new Uint8Array(4 + secret.length + value.length)
    buf.set(uint32be(iter + 1))
    buf.set(secret, 4)
    buf.set(value, 4 + secret.length)
    res.set(await digest('sha256', buf), iter * 32)
  }
  return res.slice(0, bits >> 3)
}


export function concat(...buffers: Uint8Array[]): Uint8Array {
  const size = buffers.reduce((acc, { length }) => acc + length, 0)
  const buf = new Uint8Array(size)
  let i = 0
  for (const buffer of buffers) {
    buf.set(buffer, i)
    i += buffer.length
  }
  return buf
}

export function lengthAndInput(input: Uint8Array) {
  return concat(uint32be(input.length), input)
}

export const deriveKey = async (publicKeyJwk: any, privateKeyJwk: any) => {
  const length = Math.ceil(parseInt('P-256'.substr(-3), 10) / 8) << 3
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: await publicKeyFromJwk(publicKeyJwk),
      },
      await privateKeyFromJwk(privateKeyJwk),
      length,
    ),
  )
  const algorithm = 'ECDH-ES+A128KW'
  const keyLength = 128;
  const apu = new Uint8Array(0)
  const apv = new Uint8Array(0)
  const encoder = new TextEncoder()
  const value = concat(
    lengthAndInput(encoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLength),
  )
  return concatKdf(sharedSecret, keyLength, value);
}

export const wrap: any = (alg: string, key: unknown, cek: Uint8Array) => {
  const size = parseInt(alg.slice(1, 4), 10)
  const algorithm = `aes${size}-wrap`
  const keyObject = createSecretKey(key as any)
  const cipher = createCipheriv(algorithm, keyObject, Buffer.alloc(8, 0xa6))
  return concat(cipher.update(cek), cipher.final())
}

export const unwrap: any = (
  alg: string,
  key: Uint8Array,
  encryptedKey: Uint8Array,
) => {
  const size = parseInt(alg.slice(1, 4), 10)
  const algorithm = `aes${size}-wrap`
  const keyObject = createSecretKey(key as any)
  const cipher = createDecipheriv(algorithm, keyObject, Buffer.alloc(8, 0xa6))
  return concat(cipher.update(encryptedKey), cipher.final())
}

export const getJweJson = async (publicKeyJwk: any, plaintext: Uint8Array, aad?: Uint8Array) => {
  // second key here is not used
  const key2 = await jose.generateKeyPair('RSA-OAEP-384')
  const enc = await new jose.GeneralEncrypt(
    plaintext
  )
  if (aad) {
    enc.setAdditionalAuthenticatedData(aad);
  }
  return enc.setProtectedHeader({ enc: 'A128GCM' })
    .addRecipient(await jose.importJWK(publicKeyJwk))
    .setUnprotectedHeader({ alg: 'ECDH-ES+A128KW' })
    .addRecipient(key2.publicKey)
    .setUnprotectedHeader({ alg: 'RSA-OAEP-384' })
    .encrypt()
}