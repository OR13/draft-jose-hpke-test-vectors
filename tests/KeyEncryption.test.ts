
import * as hpke from '../src'


describe('KeyEncryption', () => {

  it.skip('Single Recipient Compact (no aad)', async () => {
    // recipient 1
    const privateKey1 = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
    const publicKey1 = await hpke.keys.publicFromPrivate(privateKey1)
    const resolvePrivateKey = (kid: string) => {
      if (kid === publicKey1.kid) {
        return privateKey1
      }
      throw new Error('Unknown kid')
    }
    // recipients as a JWKS
    const recipientPublicKeys = {
      "keys": [
        publicKey1
      ]
    }
    const plaintext = new TextEncoder().encode(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
    const contentEncryptionAlgorithm = 'A128GCM'
    const jwe = await hpke.KeyEncryption.encrypt({
      protectedHeader: { enc: contentEncryptionAlgorithm },
      plaintext,
      recipients: recipientPublicKeys
    }, {serialization: 'Compact'});

    const privateKey = resolvePrivateKey(publicKey1.kid)
    // simulate having only one of the recipient private keys
    const recipientPrivateKeys = { "keys": [privateKey] }
    const decryption = await hpke.KeyEncryption.decrypt({ jwe , privateKeys: recipientPrivateKeys }, {serialization: 'Compact'})
    expect(new TextDecoder().decode(decryption.plaintext)).toBe(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
    expect(decryption.aad).toBeUndefined()

  })

  it('Multiple Recipients General JSON', async () => {
    // recipient 1
    const privateKey1 = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
    const publicKey1 = await hpke.keys.publicFromPrivate(privateKey1)

    // recipient 2
    const privateKey2 = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
    const publicKey2 = await hpke.keys.publicFromPrivate(privateKey2)

    const resolvePrivateKey = (kid: string) => {
      if (kid === publicKey1.kid) {
        return privateKey1
      }
      if (kid === publicKey2.kid) {
        return privateKey2
      }
      throw new Error('Unknown kid')
    }

    // recipients as a JWKS
    const recipientPublicKeys = {
      "keys": [
        publicKey1,
        publicKey2
      ]
    }

    const plaintext = new TextEncoder().encode(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
    const aad = new TextEncoder().encode('💀 aad')
    const contentEncryptionAlgorithm = 'A128GCM'

    const ciphertext = await hpke.KeyEncryption.encrypt({
      protectedHeader: { enc: contentEncryptionAlgorithm },
      plaintext,
      additionalAuthenticatedData: aad,
      recipients: recipientPublicKeys
    });

    for (const recipient of recipientPublicKeys.keys) {
      const privateKey = resolvePrivateKey(recipient.kid)
      // simulate having only one of the recipient private keys
      const recipientPrivateKeys = { "keys": [privateKey] }
      const decryption = await hpke.KeyEncryption.decrypt({ jwe: ciphertext, privateKeys: recipientPrivateKeys })
      expect(new TextDecoder().decode(decryption.plaintext)).toBe(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
      expect(decryption.aad).toBeDefined()
      expect(new TextDecoder().decode(decryption.aad)).toBe('💀 aad');
    }

  })
})
