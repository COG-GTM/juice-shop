/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import logger from '../logger'
import * as utils from '../utils'
import * as security from '../insecurity'

const publishJwtPublicKey = async () => {
  try {
    await fs.writeFile('encryptionkeys/jwt.pub', security.publicKey)
  } catch (err) {
    logger.warn('Error writing encryptionkeys/jwt.pub: ' + utils.getErrorMessage(err))
  }
}
export default publishJwtPublicKey
