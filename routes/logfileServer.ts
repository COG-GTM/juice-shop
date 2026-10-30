/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

export function serveLogFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!security.isAdmin(req)) {
      res.status(403).json({ error: 'Malicious activity detected' })
      return
    }

    const file = req.params.file

    if (!file.includes('/') && !file.includes('\\') && path.basename(file) === file) {
      res.sendFile(path.resolve('logs/', file))
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
