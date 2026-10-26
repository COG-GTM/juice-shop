/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    } else if (file === path.basename(security.privateKeyFile)) {
      res.status(403)
      next(new Error('Access to the JWT signing key is forbidden!'))
    } else if (file === 'jwt.pub') {
      res.type('text/plain').send(security.publicKey)
    } else {
      res.sendFile(path.resolve('encryptionkeys/', file))
    }
  }
}
