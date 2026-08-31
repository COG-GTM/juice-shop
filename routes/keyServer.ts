/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import { privateKeyFile } from '../lib/insecurity'

const signingKeyFile = path.basename(privateKeyFile)

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    } else if (file === signingKeyFile) {
      res.status(403)
      next(new Error('Access to the JWT signing key is forbidden!'))
    } else {
      res.sendFile(path.resolve('encryptionkeys/', file))
    }
  }
}
