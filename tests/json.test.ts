
import * as hpke from '../src'

it('encrypt / decrypt', async () => {
  const privateKeyJwk = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
  const publicKeyJwk = await hpke.keys.publicFromPrivate(privateKeyJwk)
  const message = `It’s a 💀 dangerous business 💀, Frodo, going out your door.`
  const plaintext = new TextEncoder().encode(message);
  const ciphertext = await hpke.json.encrypt(plaintext, publicKeyJwk)
  // {
  //   "unprotected": {
  //     "recipients": [
  //       {
  //         "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:5QPavpXFqMyRfGw6uocROgobSyjyrhPdo5SllaZ-Nvo",
  //         "encapsulated_key": "BCVMwqZyG2dV0ghOnvLUjbRsZH9rOa-qYAfimsOs_Bk4jUSuSIsqz-u66zNEw0papvR8SEn3oPkV7qDb2KxQTJ4",
  //         "encrypted_key": "dViGsJMkfIDvdqbtfHx3l2oaQ-6ONU890oPyOwmTOOQ"
  //       }
  //     ]
  //   },
  //   "iv": "QT9drgDCaosnyQei",
  //   "ciphertext": "6nQLs8bXUh0vHjSk_q4-eu4XJVXdx_AUZeQpDpnnbPguVjS1aYQjPfG9qIZ1zKm9k0Fh7eL5lgyzbyA8OgmPGVa8EooEl1H9bvmnib6jzP9H4A"
  // }
  const recovered = await hpke.json.decrypt(ciphertext, privateKeyJwk)
  expect(new TextDecoder().decode(recovered)).toBe(message);
})