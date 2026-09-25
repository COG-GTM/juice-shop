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
      if (file === 'jwt.pub') {
        /* Streamed as a string because the serve-index middleware wrapping this route rewrites res.end() arguments */
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
