/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { writeFile } from 'node:fs/promises'
import logger from '../logger'
import * as utils from '../utils'
import { publicKey } from '../insecurity'

const publishJwtPublicKey = async () => {
  try {
    await writeFile(path.resolve('encryptionkeys/jwt.pub'), publicKey)
  } catch (err) {
    logger.warn('Error writing JWT public key to /encryptionkeys folder: ' + utils.getErrorMessage(err))
  }
}

export default publishJwtPublicKey
