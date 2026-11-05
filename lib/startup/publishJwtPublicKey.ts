/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { writeFile } from 'node:fs/promises'
import logger from '../logger'
import { publicKey } from '../insecurity'

const publishJwtPublicKey = async () => {
  try {
    await writeFile(path.resolve('encryptionkeys/jwt.pub'), publicKey)
  } catch (err) {
    logger.warn(`Could not write JWT public key to encryptionkeys/jwt.pub: ${(err as Error).message}`)
  }
}

export default publishJwtPublicKey
