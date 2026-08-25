/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import { privateKeyFile, publicKey } from '../lib/insecurity'

const protectedKeyFile = path.basename(privateKeyFile)

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file === protectedKeyFile) {
      res.status(403)
      return next(new Error('Access to the JWT signing key is forbidden!'))
    } else if (file === 'jwt.pub') {
      res.type('text/plain').end(publicKey)
    } else if (!file.includes('/')) {
      res.sendFile(path.resolve('encryptionkeys/', file))
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
