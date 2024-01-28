
import crypto from 'crypto'

export const generateContentEncryptionKey = async (enc: string) => {
  let contentEncryptionKey = undefined
  if (enc == 'A128GCM') {
    contentEncryptionKey = crypto.randomBytes(16) // possibly wrong
  }
  if (contentEncryptionKey) {
    return contentEncryptionKey
  } else {
    throw new Error('Unsupported content encryption algorithm')
  }
}
