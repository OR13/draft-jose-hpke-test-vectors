# JOSE HPKE Test Vectors

[![CI](https://github.com/OR13/draft-jose-hpke-test-vectors/actions/workflows/ci.yml/badge.svg)](https://github.com/OR13/draft-jose-hpke-test-vectors/actions/workflows/ci.yml)
![Branches](./badges/coverage-branches.svg)
![Functions](./badges/coverage-functions.svg)
![Lines](./badges/coverage-lines.svg)
![Statements](./badges/coverage-statements.svg)
![Jest coverage](./badges/coverage-jest%20coverage.svg)


🚧 Experimental 🔥

--> [draft-rha-jose-hpke-encrypt](https://datatracker.ietf.org/doc/draft-rha-jose-hpke-encrypt/)

## Compact

```ts

import * as hpke from '../src'

it('encrypt / decrypt', async () => {
  const privateKeyJwk = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
  // {
  //   kid: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:om1gRRYAiZ3CRMlvnSizjYzaX-t94m96A5DWzM78lm0',
  //   alg: 'HPKE-Base-P256-SHA256-AES128GCM',
  //   kty: 'EC',
  //   crv: 'P-256',
  //   x: 'UQoMdtvzzboEH-Jj41mfnw7FT6HdJhemsP7R5SJRDcM',
  //   y: 'I4TQnPtVyFwKz_G8DLcAPvx1QwHCIjlWw6_WOB6tLDo',
  //   d: 'lhDRw6qmjx1cX-1X2P3oljMPTlvS-wsosdGejGbxMss'
  // }
  const publicKeyJwk = await hpke.keys.publicFromPrivate(privateKeyJwk)
  // {
  //   kid: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:zLL3uvca9qDXqK1UysySHW720kcKVcEqOf7KBIVZg6Q',
  //   alg: 'HPKE-Base-P256-SHA256-AES128GCM',
  //   kty: 'EC',
  //   crv: 'P-256',
  //   x: 'W-70J8fA-XcYE3PiSIy_wNz-TQ_-j_QrOGLAo30YuN0',
  //   y: 'v6DySTYHurdTKwNa-AN7LwHSh-jN9x4a3uO1r38b1EI'
  // }
  const message = `It’s a 💀 dangerous business 💀, Frodo, going out your door.`
  const plaintext = new TextEncoder().encode(message);
  const ciphertext = await hpke.compact.encrypt(plaintext, publicKeyJwk)
  // eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIn0.BKYjy3VbemjsKyEPg6_LJpKHcSsu4igA5O2zaejWI16RbM9_uA3xjBskT3KfzJ5IPdBa5m68o93TYfY1QBeQ0EA.._4eoNOUDKEpiInbI5Bix-KIOMXIpP6vKDlGZ9f8lrN6db4Nvqis1vxvnNmgQEOTPLS81DPlHVV184q6RHGmWzn6gILTFCOu-zYKesdazqIf3tA.
  const recovered = await hpke.compact.decrypt(ciphertext, privateKeyJwk)
  expect(new TextDecoder().decode(recovered)).toBe(message);
```

## JSON

```ts

import * as hpke from '../src'

it('encrypt / decrypt', async () => {
  // recipient 1
  const privateKey1 = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
  const publicKey1 = await hpke.keys.publicFromPrivate(privateKey1)

  // recipient 2
  const privateKey2 = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
  privateKey2.alg = 'ECDH-ES+A128KW' // overwrite algorithm
  const publicKey2 = await hpke.keys.publicFromPrivate(privateKey2)

  const resolvePrivateKey = (kid: string): any =>{
    if (kid === publicKey1.kid){
      return privateKey1
    }
    if (kid === publicKey2.kid){
      return privateKey2
    }
    throw new Error('Unknown kid')
  }

  // recipients as a JWKS
  const recipientPublicKeys = {
    "keys" : [
      publicKey1,
      publicKey2
    ]
  }

  const plaintext = new TextEncoder().encode(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
  const aad = new TextEncoder().encode('💀 aad')
  const contentEncryptionAlgorithm = 'A128GCM'

  const ciphertext = await hpke.json.encrypt({
    protectedHeader: { enc: contentEncryptionAlgorithm },
    plaintext,
    additionalAuthenticatedData: aad,
    recipients: recipientPublicKeys
  });
  // {
  //     "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
  //     "ciphertext": "F0xDJfbjd3sjLUEv2Q3dArzUSITUw9dTiqIpIOWhzS-akIq2_rw68QdGSurWRhOR_I2sXZ0Xr9IP5yjjpJztD_skrvkpjlzuxZ2-6JUkw4Xnkg",
  //     "iv": "ZQ-VkP5H9iQtuUyj",
  //     "aad": "8J-SgCBhYWQ",
  //     "recipients": [
  //       {
  //         "encrypted_key": "AV-gprT2_-G0XNnN_N9b9iSShXE9fQ0SpV6aAX-JxFnYNc7SU0BfTHl5TMNPaQBa",
  //         "header": {
  //           "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:8uKV5Zqa7Y9UPMIzixTtAy8sOp7oHjYndUxQWyIJpxM",
  //           "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  //           "encapsulated_key": "BIZ4PEqGG9GSMSLPgT9o3gHkaIMWtLNauTuwMXXp-_cFSnH-24IUoJzISK3thEcosTq67KOWYK9jV9grPSpoMrw"
  //         }
  //       },
  //       {
  //         "encrypted_key": "5mVD6P9ySVkhpVEUL2Qy5Ka7Ttd49HwZjhVfoFj1JQFY2Yoa5U9pnQ",
  //         "header": {
  //           "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:bM_mRz5jXbHYtOXgmXuAoj5vOc62aC5s206AAKc7lI4",
  //           "alg": "ECDH-ES+A128KW",
  //           "epk": {
  //             "kty": "EC",
  //             "crv": "P-256",
  //             "x": "A6BhREIaSalw6rdFjXyezWXkKbamSdD5qOR6NZMJI-c",
  //             "y": "pPZ41NOAuFYuVDNVprSkQUs__L7YLMbnZws6FLXjB4U"
  //           }
  //         }
  //       }
  //     ]
  //   }
  for (const recipient of recipientPublicKeys.keys){
    const privateKey = resolvePrivateKey(recipient.kid)
    // simulate having only one of the recipient private keys
    const recipientPrivateKeys =  { "keys": [ privateKey ] }
    const decryption = await hpke.json.decrypt({ jwe: ciphertext, privateKeys: recipientPrivateKeys})
    expect(new TextDecoder().decode(decryption.plaintext)).toBe(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
    expect(new TextDecoder().decode(decryption.aad)).toBe('💀 aad');
  }
})
```

## Develop

```bash
nvm use 18
# Now using node v18.17.0 (npm v9.6.7)
npm i
npm t
```
