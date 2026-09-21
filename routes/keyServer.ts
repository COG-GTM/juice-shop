/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveKeyFiles () {
  const keysDir = path.resolve('encryptionkeys')

  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    const target = path.resolve(keysDir, file)

    if (file === path.basename(file) && target.startsWith(keysDir + path.sep)) {
      res.sendFile(target)
    } else {
      res.status(403)
      next(new Error('File names cannot contain path separators!'))
    }
  }
}
