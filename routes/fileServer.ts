/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

const ftpRoot = path.resolve('ftp/')
const allowlistedFileTypes = ['.md', '.pdf']
const allowlistedFileNames = ['incident-support.kdbx']

export function servePublicFiles () {
  return async ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    } else {
      await verify(file, res, next)
    }
  }

  async function verify (file: string, res: Response, next: NextFunction) {
    if (!isAllowlistedFileName(file)) {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
      return
    }

    try {
      if (!(await listServedFiles()).has(file)) {
        res.status(404)
        next(new Error('File not found!'))
        return
      }
    } catch (error) {
      next(error)
      return
    }

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })

    res.sendFile(file, { root: ftpRoot, dotfiles: 'deny' })
  }

  // Express has already URL-decoded the parameter once, so a remaining '%' indicates double encoding such as %2500
  function isAllowlistedFileName (file: string) {
    if (!file || file.includes('\0') || file.includes('%') || file.includes('\\') || path.basename(file) !== file) {
      return false
    }
    return allowlistedFileTypes.some(type => utils.endsWith(file, type)) || allowlistedFileNames.includes(file)
  }

  async function listServedFiles () {
    const entries = await fs.readdir(ftpRoot, { withFileTypes: true })
    return new Set(entries.filter(entry => entry.isFile()).map(entry => entry.name))
  }
}
