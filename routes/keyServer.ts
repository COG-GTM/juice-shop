/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const publicKeyFiles = new Set(['jwt.pub'])

export function denyDirectoryListing () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.path === '/') {
      res.status(404)
      next(new Error('Directory listing is not available!'))
      return
    }
    next()
  }
}

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!publicKeyFiles.has(file)) {
      res.status(403)
      next(new Error('Only public key files can be requested!'))
      return
    }
    res.sendFile(path.resolve('encryptionkeys/', file))
  }
}
