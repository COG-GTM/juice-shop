/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const publicFtpDirectory = path.resolve('ftp')
const publicFtpFiles = [/^legal\.md$/, /^order_[0-9a-f]{4}-[0-9a-f]{16}\.pdf$/]

export function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (isPublicFile(file)) {
      const resolvedPath = path.resolve(publicFtpDirectory, file)
      if (resolvedPath.startsWith(publicFtpDirectory + path.sep) && path.dirname(resolvedPath) === publicFtpDirectory) {
        res.sendFile(resolvedPath)
        return
      }
    }
    res.status(403)
    next(new Error('File not available!'))
  }

  function isPublicFile (file: string) {
    return typeof file === 'string' && publicFtpFiles.some(pattern => pattern.test(file))
  }
}
