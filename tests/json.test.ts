
import * as hpke from '../src'

it('encrypt / decrypt', async () => {
  // recipient 1
  const privateKey1 = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
  const publicKey1 = await hpke.keys.publicFromPrivate(privateKey1)

  // recipient 2
  const privateKey2 = await hpke.keys.generate('HPKE-Base-P256-SHA256-AES128GCM')
  const publicKey2 = await hpke.keys.publicFromPrivate(privateKey2)

  const resolvePrivateKey = (kid: string) =>{
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

  console.log(JSON.stringify(ciphertext, null, 2))
  // {
  //   "iv": "jGA1495md8IaMrbO",
  //   "ciphertext": "L7sD6Y2RfnlElDF_la5eB...jGeNoaZZFp_F6yZ3K-uqg",
  //   "recipients": [
  //     {
  //       "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:ROv0KdmDUQBERQuiTnp5S-Ki4rgjqPtTX_w1dTfPsWg",
  //       "encapsulated_key": "BIv2gwvAGZzp1...B36hqdTcZh41jH7LlCChU",
  //       "encrypted_key": "CI4_LXJdHLWsvOA6SQGMSH3...uDpdrw5Fn0Po5Ho9"
  //     },
  //     {
  //       "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:C4LqgFbEPz97P9wRoS1DyBk4FT7CxOuPNn9a8gyoxOU",
  //       "encapsulated_key": "BK_M7wMl1NQPy_UGGxOb6...lvppxiDCnCEqPT4isU",
  //       "encrypted_key": "MuTYjX0g1emKI481spI...maP_T9RfsZCmSDCqS5"
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