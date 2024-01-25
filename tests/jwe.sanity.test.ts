
import * as jose from 'jose'

import * as mixed from '../src/mixedKeyAgreement'

it('jwe', async () => {
  const key1 = await jose.generateKeyPair('ECDH-ES+A128KW', { crv: 'P-256', extractable: true })
  const key2 = await jose.generateKeyPair('RSA-OAEP-384')
  const message = new TextEncoder().encode('✨ It’s a dangerous business, Frodo, going out your door. ✨')
  const aad = new TextEncoder().encode('💀 aad')
  const jwe = await new jose.GeneralEncrypt(
    message
  )
    .setAdditionalAuthenticatedData(aad)
    .setProtectedHeader({ enc: 'A128GCM' })
    .addRecipient(key1.publicKey)
    .setUnprotectedHeader({ alg: 'ECDH-ES+A128KW' })
    .addRecipient(key2.publicKey)
    .setUnprotectedHeader({ alg: 'RSA-OAEP-384' })
    .encrypt()

  // console.log(JSON.stringify(jwe, null, 2))
  // {
  //   "ciphertext": "x8fgMdcojbNSO0Om6TX1ORXYsGMWj0pB5Ro3GL4r7CPppN95bNEXhKULAyxL3J7vMEXuLDfq3438u0btipNZZA",
  //   "iv": "E3Lmiixm3MJeGWz8",
  //   "recipients": [
  //     {
  //       "encrypted_key": "LszO6Tu-Q9go9hwc7xW8VBt8rVTFaj9r-tXRHgoYdY-BRnrYvuAacQ",
  //       "header": {
  //         "alg": "ECDH-ES+A256KW",
  //         "epk": {
  //           "x": "XH07KuNzDMeUez-RX2GuN_OCqbq3UMiYzFswoQYURkU",
  //           "crv": "P-256",
  //           "kty": "EC",
  //           "y": "IzYPOxs7CnqYBDe0lq6c8R1hMLSnsBvdl-Y5213GWkE"
  //         }
  //       }
  //     },
  //     {
  //       "encrypted_key": "DrcQqFT0xQOLX4C63TkO...nBnsxFmjvfJLw_Gjz90JmirIs_3w",
  //       "header": {
  //         "alg": "RSA-OAEP-384"
  //       }
  //     }
  //   ],
  //   "tag": "kamMw0juZIzctqovBaRzLQ",
  //   "aad": "8J-SgCBhYWQ",
  //   "protected": "eyJlbmMiOiJBMjU2R0NNIn0"
  // }

  const { plaintext, protectedHeader, additionalAuthenticatedData } = await jose.generalDecrypt(jwe, key1.privateKey);
  expect(new TextDecoder().decode(additionalAuthenticatedData)).toBe('💀 aad')
  expect(new TextDecoder().decode(plaintext)).toBe('✨ It’s a dangerous business, Frodo, going out your door. ✨')
  expect(protectedHeader).toEqual({
    "enc": "A128GCM"
  })

  // some extra tests here to confirm key wrapping basics
  const [r0] = jwe.recipients as any;
  const sharedSecret = await mixed.deriveKey( r0.header.epk, await jose.exportJWK(key1.privateKey))
  const encryptedKey = jose.base64url.decode(r0.encrypted_key)
  const cek = mixed.unwrap('A128KW', sharedSecret, encryptedKey)
  const kwkc = mixed.wrap('A128KW', sharedSecret, cek)
  expect(encryptedKey).toEqual(kwkc)

})