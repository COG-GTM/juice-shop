/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    const logsDir = path.resolve('logs')
    const filePath = path.join(logsDir, file)

    if (!file.includes('/') && !file.includes('\\') && filePath.startsWith(logsDir + path.sep)) {
      res.sendFile(filePath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes or backslashes!'))
    }
  }
}
