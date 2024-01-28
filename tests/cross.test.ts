
import * as hpke from '../src'

import * as jose from 'jose'


it.only('encrypt (theirs) / decrypt (ours)', async () => {
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


    // simulate having only one of the recipient private keys
    const recipientPrivateKeys =  { "keys": [ await jose.exportJWK(key1.privateKey) as any ] }
    const decryption = await hpke.json.decrypt({ jwe, privateKeys: recipientPrivateKeys})
    expect(new TextDecoder().decode(decryption.plaintext)).toBe(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
    expect(new TextDecoder().decode(decryption.aad)).toBe('💀 aad');
})

it('encrypt (ours) / decrypt (theirs)', async () => {
  // recipient 2
  const privateKey2 = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
  privateKey2.alg = 'ECDH-ES+A128KW' // overwrite algorithm
  const publicKey2 = await hpke.keys.publicFromPrivate(privateKey2)
  // recipients as a JWKS
  const recipientPublicKeys = {
    "keys" : [
      publicKey2
    ]
  }
  const plaintext = new TextEncoder().encode(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
  const aad = new TextEncoder().encode('💀 aad')
  const contentEncryptionAlgorithm = 'A128GCM'
  const jwe = await hpke.json.encrypt({
    protectedHeader: { enc: contentEncryptionAlgorithm },
    plaintext,
    additionalAuthenticatedData: aad,
    recipients: recipientPublicKeys
  });
  const decrypted = await jose.generalDecrypt(jwe, await jose.importJWK(privateKey2));
  expect(new TextDecoder().decode(decrypted.additionalAuthenticatedData)).toBe('💀 aad')
  expect(new TextDecoder().decode(decrypted.plaintext)).toBe('✨ It’s a dangerous business, Frodo, going out your door. ✨')
  expect(decrypted.protectedHeader).toEqual({
    "enc": "A128GCM"
  })
})