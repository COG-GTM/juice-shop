/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const publicKeyFiles = ['jwt.pub']

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }

    const keyDirectory = path.resolve('encryptionkeys/')
    if (!fs.readdirSync(keyDirectory).includes(file)) {
      res.status(404)
      next(new Error('File not found!'))
    } else if (!publicKeyFiles.includes(file)) {
      res.status(403)
      next(new Error('Only public key files can be downloaded!'))
    } else {
      res.sendFile(path.join(keyDirectory, file))
    }
  }
}
