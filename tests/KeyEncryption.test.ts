
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

  const ciphertext = await hpke.KeyEncryption.encrypt({
    protectedHeader: { enc: contentEncryptionAlgorithm },
    plaintext,
    additionalAuthenticatedData: aad,
    recipients: recipientPublicKeys
  });

  // console.log(JSON.stringify(ciphertext, null, 2))
  // {
  //   "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
  //   "ciphertext": "k3fVE4ArW8MLcE5WDXkloMPlTFj-eswCkpLsiH1ySe1YfxWBhhgJDPCoQeJiZAzK3aDbFPzEVUA-Wir_Q-dDqTO8",
  //   "iv": "tHHWmjf2hlGnfGy2",
  //   "aad": "8J-SgCBhYWQ",
  //   "tag": "V2HpcAadnYaXoSyl3I1OHA",
  //   "recipients": [
  //     {
  //       "encrypted_key": "GfHHxdoVxvBUH5cI8xtzNvSU2VI3yc2CSacUCgvClkU",
  //       "header": {
  //         "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:ksLOGnJGcxEL4YZJALKnudgouNhA5XQkfAfXax47QEI",
  //         "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  //         "encapsulated_key": "BLCG3FZx-QeVpQf0-01r7rGhw94rusVO2YKjLq1ydEREbwNIgKFv7xXn5Bl1SvJ2JfvLp6rnyxA4E6nQxaZTT1o"
  //       }
  //     },
  //     {
  //       "encrypted_key": "0H5K0ZXpZhRpx1Jqrjb4X2Q-cDxi-nISc06QtKvZSaU",
  //       "header": {
  //         "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:5e_H1gwsc1QmmBSbVul2TjYirvIXFcsMxXtnVBL5KG8",
  //         "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  //         "encapsulated_key": "BBScFHps3XGVQ9yyg5PoPkprqxjopbYQclSGV1SozTXPowOlFu9nKmXKc0SpOXY7WDiWKDm9X___kknmVEEbEmQ"
  //       }
  //     }
  //   ]
  // }

 

  for (const recipient of recipientPublicKeys.keys){
    const privateKey = resolvePrivateKey(recipient.kid)
    // simulate having only one of the recipient private keys
    const recipientPrivateKeys =  { "keys": [ privateKey ] }
    const decryption = await hpke.KeyEncryption.decrypt({ jwe: ciphertext, privateKeys: recipientPrivateKeys})
    expect(new TextDecoder().decode(decryption.plaintext)).toBe(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
    expect(new TextDecoder().decode(decryption.aad)).toBe('💀 aad');
  }
  
})