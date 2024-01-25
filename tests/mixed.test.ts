
import * as hpke from '../src'

import * as jose from 'jose'

it.skip('encrypt / decrypt', async () => {
  // recipient 1
  const privateKey1 = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
  const publicKey1 = await hpke.keys.publicFromPrivate(privateKey1)

  // recipient 2
  const key2 = await jose.generateKeyPair('ECDH-ES+A128KW', { crv: 'P-256', extractable: true })
  const privateKey2 = await jose.exportJWK(key2.privateKey);
  privateKey2.alg = 'ECDH-ES+A128KW'
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

  // console.log(JSON.stringify(ciphertext, null, 2))
  // {
  //   "ciphertext": "fBQXw5hJITDMttWjUIHXETRvDL2_zOEWHbW1Q5ILaYawVUzisXWBA0GIsqncEIO1qAzCuAuW1MxHC3F9YIsAT51Wrp3Nrmp4f8zOMHlUJa1uJQ",
  //   "iv": "QzbgK6-BrK5UEy9a",
  //   "recipients": [
  //     {
  //       "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:bF7B4GzHR4eunXXm_W-aioPexcK2Qkg3ie7M94lIVBM",
  //       "encapsulated_key": "BBc78D-qj88ZZoORf_p7JDnYMnIrFt_tPUgZ9vt8bHyZqCQmuWuXgeoqab15OfnYFBgh-sm6yG1sSEKNpXHEqcE",
  //       "encrypted_key": "9Bk5jC6zRg0WKAWOfXT2y3UnIL_MPNOp38Ugt9YJ5HWUIxIM_j4YD3cIwp5td62j"
  //     },
  //     {
  //       "encrypted_key": "ZCqaqeixfrtaLGOkDduhdZpsggnLi0MQ",
  //       "header": {
  //         "alg": "ECDH-ES+A128KW",
  //         "epk": {
  //           "x": "iBVW_DI6pry9e_SbZvjySVtsXJqKF3Z90BcYfC3rtDQ",
  //           "crv": "P-256",
  //           "kty": "EC",
  //           "y": "yTUAljNvl5b-EC1GlyjobgFz3_6ufDa8KQaQo9QDsQw"
  //         }
  //       }
  //     }
  //   ],
  //   "aad": "8J-SgCBhYWQ",
  //   "protected": "eyJlbmMiOiJBMTI4R0NNIn0"
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