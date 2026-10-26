/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import logger from '../logger'
import * as utils from '../utils'
import { publicKey } from '../insecurity'

const publishJwtPublicKey = async () => {
  try {
    await fs.writeFile('encryptionkeys/jwt.pub', publicKey)
  } catch (err) {
    logger.warn('Could not write encryptionkeys/jwt.pub (still served from memory): ' + utils.getErrorMessage(err))
  }
}
export default publishJwtPublicKey
