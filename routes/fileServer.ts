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
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    const ftpFolder = path.resolve('ftp/')
    const filePath = path.resolve(ftpFolder, file)
    const fileName = path.basename(filePath)

    if (file && !containsEncodedOrControlCharacters(file) && path.dirname(filePath) === ftpFolder && isAllowlistedFile(fileName)) {
      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return fileName.toLowerCase() === 'acquisitions.md' })

      res.sendFile(filePath)
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function containsEncodedOrControlCharacters (param: string) {
    return /[%\\\p{Cc}]/u.test(param)
  }

  function isAllowlistedFile (fileName: string) {
    return endsWithAllowlistedFileType(fileName) || fileName === 'incident-support.kdbx'
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
