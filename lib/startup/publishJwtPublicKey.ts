/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { writeFile } from 'node:fs/promises'
import { publicKey } from '../insecurity'

const publishJwtPublicKey = async () => {
  await writeFile(path.resolve('encryptionkeys/jwt.pub'), publicKey)
}

export default publishJwtPublicKey
