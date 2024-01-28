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

  const resolvePrivateKey = (kid: string): any => {
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
  
  const ciphertext = await hpke.json.encrypt({
    protectedHeader: { enc: 'A128GCM' },
    plaintext: new TextEncoder().encode(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`),
    additionalAuthenticatedData: new TextEncoder().encode('💀 aad'),
    recipients: recipientPublicKeys
  });
  // {
  //   "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
  //   "ciphertext": "t7XOvW1SZgf-3fz7ZNSDiEEUKRdI9MdblC-8wLysN49ov0erROQDieZ-EFn0QnDFZw5RcGPMLWvO8ZkHfOsgzSld",
  //   "iv": "Sl0fLuINvzicEgzQ",
  //   "aad": "8J-SgCBhYWQ",
  //   "tag": "xy3xYOfBM5ObzNXdeppkyw",
  //   "recipients": [
  //     {
  //       "encrypted_key": "tURMb3-zPMhHoHZUGlnVUyQhscrpQenjrRKorM2DoDo",
  //       "header": {
  //         "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:RLaSa8XtodlM3fLoS7IGBL21lgXOP-nVg7obhAf8AVs",
  //         "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  //         "encapsulated_key": "BESPDLvUeBwkSsQhrZpY4lS-fFE_3LcQCh8TuUsphvrSd1oapl6SNg-Hs0poV8rn-KCbyWGuY6IAABpRlNUiH3g"
  //       }
  //     },
  //     {
  //       "encrypted_key": "zuVnoUXttYnMW9FtxXPkSD_rF__Udixs",
  //       "header": {
  //         "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:2M7TcrbAuR5riiLzxwWN_NR6Js8fMFtu-tVLakgqoAo",
  //         "alg": "ECDH-ES+A128KW",
  //         "epk": {
  //           "kty": "EC",
  //           "crv": "P-256",
  //           "x": "H5jZ_QhKH8XfqvKT6lqWO0yGSMLA8VukIDmdHzQnca4",
  //           "y": "BmWr4pxMoQI_BJaachjhP_YfMKXNmStHiQGkKFDXdaE"
  //         }
  //       }
  //     }
  //   ]
  // }
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
