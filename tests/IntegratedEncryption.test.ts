
import * as hpke from '../src'


describe('encrypt / decrypt ', ()=>{
  it('Compact', async () => {
    const privateKeyJwk = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
    const publicKeyJwk = await hpke.keys.publicFromPrivate(privateKeyJwk)
    const message = `It’s a 💀 dangerous business 💀, Frodo, going out your door.`
    const plaintext = new TextEncoder().encode(message);
    const jwe = await hpke.IntegratedEncryption.encrypt(plaintext, publicKeyJwk)
    expect(jwe.split('.').length).toBe(5) // compact jwe is default
    const recovered = await hpke.IntegratedEncryption.decrypt(jwe, privateKeyJwk)
    expect(new TextDecoder().decode(recovered)).toBe(message);
    console.log(jwe)
  })
  it('JSON', async () => {
    const privateKeyJwk = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
    const publicKeyJwk = await hpke.keys.publicFromPrivate(privateKeyJwk)
    const message = `It’s a 💀 dangerous business 💀, Frodo, going out your door.`
    const plaintext = new TextEncoder().encode(message);
    const jwe = await hpke.IntegratedEncryption.encrypt(plaintext, publicKeyJwk, { serialization: 'GeneralJson'})
    console.log(jwe)
    expect(jwe.protected).toBeDefined()
    expect(jwe.ciphertext).toBeDefined()
    expect(jwe.iv).toBeUndefined()
    expect(jwe.tag).toBeUndefined()
    expect(jwe.encrypted_key).toBeUndefined()
    const recovered = await hpke.IntegratedEncryption.decrypt(jwe, privateKeyJwk, { serialization: 'GeneralJson'})
    expect(new TextDecoder().decode(recovered)).toBe(message);
  })
})
