/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export const publicFiles: readonly string[] = ['legal.md', 'announcement_encrypted.md']

export function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = normalizeFileName(params.file)

    if (file !== null && publicFiles.includes(file)) {
      res.sendFile(path.resolve('ftp/', file))
    } else {
      res.status(403)
      next(new Error('File not found or not publicly accessible!'))
    }
  }

  function normalizeFileName (file?: string) {
    if (typeof file !== 'string' || file.length === 0) return null
    let decoded = file
    try {
      while (decoded.includes('%')) {
        const next = decodeURIComponent(decoded)
        if (next === decoded) break
        decoded = next
      }
    } catch {
      return null
    }
    if (decoded.includes('\0') || decoded.includes('/') || decoded.includes('\\')) return null
    return path.basename(decoded).toLowerCase()
  }
}
