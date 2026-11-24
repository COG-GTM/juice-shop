/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const keysDir = path.resolve('encryptionkeys')

function isPlainFileName (file: string) {
  return !/[/\\:\0]/.test(file) &&
    file !== '.' && file !== '..' &&
    path.posix.basename(file) === file &&
    path.win32.basename(file) === file
}

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (isPlainFileName(file)) {
      res.sendFile(file, { root: keysDir })
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
