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

    if (!file.includes('/')) {
      // jwt.pub is served from the runtime key pair so the Forged Signed JWT challenge stays solvable
      if (file === 'jwt.pub') {
        res.type('text/plain').end(security.publicKey)
      } else {
        res.sendFile(path.resolve('encryptionkeys/', file))
      }
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
