/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

const ftpFolder = path.resolve('ftp/')
const allowlistedFileTypes = ['.md', '.pdf']
const allowlistedFileNames = ['incident-support.kdbx']

export function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    } else if (containsNullByteOrEncoding(file)) {
      res.status(403)
      next(new Error('File names cannot contain null bytes or encoded characters!'))
    } else {
      verify(file, res, next)
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    const resolvedPath = path.resolve(ftpFolder, file)
    if (file && isAllowlisted(file) && path.dirname(resolvedPath) === ftpFolder) {
      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })

      res.sendFile(resolvedPath)
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  // Express already URL-decoded the parameter once, so any remaining '%' indicates double encoding such as %2500
  function containsNullByteOrEncoding (file: string) {
    return file.includes('\0') || file.includes('%')
  }

  function isAllowlisted (file: string) {
    return allowlistedFileTypes.some(type => utils.endsWith(file, type)) || allowlistedFileNames.includes(file)
  }
}
