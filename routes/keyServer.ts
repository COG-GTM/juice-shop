/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const safeFileName = /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/

const publicKeyFiles = new Set(['jwt.pub'])

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!safeFileName.test(file)) {
      res.status(403)
      next(new Error('Invalid file name!'))
    } else if (publicKeyFiles.has(file)) {
      res.sendFile(path.resolve('encryptionkeys/', file))
    } else {
      res.status(404)
      next(new Error('File not found!'))
    }
  }
}
