/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const publicFiles = new Set(['legal.md'])

export function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (publicFiles.has(file)) {
      res.sendFile(path.resolve('ftp/', file))
    } else {
      res.status(404)
      next(new Error('File not found!'))
    }
  }
}
