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
    if (containsNullByte(file)) {
      verifyAttemptedPoisonNullByteExploit(file.split(/\0|%00/)[0])
      res.status(403)
      next(new Error('File names cannot contain null bytes!'))
      return
    }

    if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
      const resolvedPath = path.resolve(ftpFolder, file)
      if (path.dirname(resolvedPath) !== ftpFolder) {
        res.status(403)
        next(new Error('File names cannot contain forward slashes!'))
        return
      }

      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })

      res.sendFile(resolvedPath)
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function verifyAttemptedPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function containsNullByte (param: string) {
    return param.includes('\0') || utils.contains(param, '%00')
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
