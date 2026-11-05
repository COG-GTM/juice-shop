/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import logger from '../logger'
import * as utils from '../utils'
import { publicKey, publicKeyFile } from '../insecurity'

const publishJwtPublicKey = async () => {
  try {
    await fs.writeFile(`encryptionkeys/${publicKeyFile}`, publicKey)
  } catch (err) {
    logger.warn('Error writing JWT public key to /encryptionkeys folder: ' + utils.getErrorMessage(err))
  }
}
export default publishJwtPublicKey
