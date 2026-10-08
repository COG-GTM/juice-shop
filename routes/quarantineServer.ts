/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import { denyFileAccess, isAdmin } from './fileServer'

const quarantineDir = path.resolve('ftp/quarantine')

export function serveQuarantineFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    const file = req.params.file

    const filePath = path.resolve(quarantineDir, file)
    if (file.includes('/') || !filePath.startsWith(quarantineDir + path.sep)) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    } else if (isAdmin(req)) {
      res.sendFile(filePath)
    } else {
      denyFileAccess(req, res, next)
    }
  }
}
