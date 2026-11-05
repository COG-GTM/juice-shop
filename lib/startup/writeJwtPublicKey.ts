/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import logger from '../logger'
import * as utils from '../utils'
import { publicKey } from '../insecurity'

const writeJwtPublicKey = async () => {
  try {
    await fs.writeFile('encryptionkeys/jwt.pub', publicKey)
  } catch (err) {
    logger.warn('Error writing JWT public key to /encryptionkeys folder: ' + utils.getErrorMessage(err))
  }
}
export default writeJwtPublicKey
