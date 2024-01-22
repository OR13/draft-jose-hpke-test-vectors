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
  const recovered = await hpke.compact.decrypt(ciphertext, privateKeyJwk)
  expect(new TextDecoder().decode(recovered)).toBe(message);
```

## Develop

```bash
nvm use 18
# Now using node v18.17.0 (npm v9.6.7)
npm i
npm t
```
