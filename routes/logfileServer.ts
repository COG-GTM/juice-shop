/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  const logsDir = path.resolve('logs')

  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    const target = path.resolve(logsDir, file)

    if (file === path.basename(file) && target.startsWith(logsDir + path.sep)) {
      res.sendFile(target)
    } else {
      res.status(403)
      next(new Error('File names cannot contain path separators!'))
    }
  }
}
