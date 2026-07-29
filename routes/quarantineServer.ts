/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { resolveInsideFolder } from '../lib/utils'

export function serveQuarantineFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = resolveInsideFolder('ftp/quarantine/', params.file)

    if (file) {
      res.sendFile(file)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
