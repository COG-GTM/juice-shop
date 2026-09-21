/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveQuarantineFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    const quarantineDir = path.resolve('ftp/quarantine')
    const resolvedFile = path.resolve(quarantineDir, file)

    if (!/[/\\\0]/.test(file) && resolvedFile.startsWith(quarantineDir + path.sep)) {
      res.sendFile(resolvedFile)
    } else {
      res.status(403)
      next(new Error('File names cannot contain path separators!'))
    }
  }
}
