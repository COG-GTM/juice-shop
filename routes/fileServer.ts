/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const publicFiles = new Set(['legal.md'])
const orderConfirmation = /^order_[0-9a-f]{4}-[0-9a-f]{16}\.pdf$/

function isPublicFile (file: string) {
  return publicFiles.has(file) || orderConfirmation.test(file)
}

export function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    } else if (isPublicFile(file)) {
      res.sendFile(path.resolve('ftp/', file))
    } else {
      res.status(404)
      next(new Error('File not found!'))
    }
  }
}
