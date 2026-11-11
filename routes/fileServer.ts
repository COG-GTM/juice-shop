/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function servePublicFiles () {
  const ftpRoot = path.resolve('ftp')

  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = decodeFully(params.file)

    if (file === null) {
      res.status(403)
      next(new Error('File names must be valid URL-encoded strings!'))
    } else if (file.includes('/') || file.includes('\\')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    } else if (file.includes('\0')) {
      res.status(403)
      next(new Error('File names cannot contain null bytes!'))
    } else {
      verify(file, res, next)
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    const filePath = path.resolve(ftpRoot, file)
    if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx')) && path.dirname(filePath) === ftpRoot) {
      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })

      res.sendFile(filePath)
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function decodeFully (value: string): string | null {
    let decoded = value
    for (let i = 0; i < 10; i++) {
      let candidate: string
      try {
        candidate = decodeURIComponent(decoded)
      } catch {
        return null
      }
      if (candidate === decoded) return decoded
      decoded = candidate
    }
    return null
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
