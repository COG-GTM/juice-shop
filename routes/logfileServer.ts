/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }

    const root = path.resolve('logs')
    const filePath = path.resolve(root, file)
    if (file.includes('\\') || path.dirname(filePath) !== root) {
      res.status(403)
      next(new Error('File names cannot contain path traversal sequences!'))
      return
    }

    res.sendFile(filePath)
  }
}
