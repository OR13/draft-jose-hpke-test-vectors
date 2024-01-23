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
  const privateKeyJwk = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
  const publicKeyJwk = await hpke.keys.publicFromPrivate(privateKeyJwk)
  const message = `It’s a 💀 dangerous business 💀, Frodo, going out your door.`
  const plaintext = new TextEncoder().encode(message);
  const ciphertext = await hpke.json.encrypt(plaintext, publicKeyJwk)
  // {
  //   "protected": "eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIiwiZW5jIjoiQUVTMTI4R0NNIn0",
  //   "unprotected": {
  //     "recipients": [
  //       {
  //         "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:mkyymiz-41bn2xNKdui5eDJ9dIVJhJk5FWqU3Ar3ZSo",
  //         "encapsulated_key": "BKScRMMcR_keKyLI6MD-PiVgj31Y5pU1NETRIIXn_6xRBuYmB3A1plI73KvhUBciggpupz99u2Xd8c2Ba_4A3tk",
  //         "encrypted_key": "aGUXW752It4SPyTBHvAFOD-p2bn9H__6Z1gdzxoFUTA"
  //       }
  //     ]
  //   },
  //   "iv": "27oAybln9XY8_jlO",
  //   "ciphertext": "cNOYxd9u0bQA-iu6P9ngRToMOdvkuUVdoX4eFsUwVVvUDWuHRCxiuFGMP3a3z1EStSR6XwWKD_llC3mTLFfs52L9gAsNQN6uInzAiz5GYMoiRw"
  // }
  const recovered = await hpke.json.decrypt(ciphertext, privateKeyJwk)
  expect(new TextDecoder().decode(recovered)).toBe(message);
})
```

## Develop

```bash
nvm use 18
# Now using node v18.17.0 (npm v9.6.7)
npm i
npm t
```
