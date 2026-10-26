/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'

const ftpRoot = path.resolve('ftp/')
const allowlistedFileTypes = ['.md', '.pdf']
const publicFileNames = ['legal.md']
const orderConfirmationFileName = /^order_[0-9a-f]{4}-[0-9a-f]{16}\.pdf$/

export function servePublicFiles () {
  return async ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    } else {
      await servePublicFile(file, res, next)
    }
  }

  async function servePublicFile (file: string, res: Response, next: NextFunction) {
    if (!hasAllowlistedFileType(file)) {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
      return
    }

    try {
      if (!isPublicFile(file) || !(await listServedFiles()).has(file)) {
        res.status(404)
        next(new Error('File not found!'))
        return
      }
    } catch (error) {
      next(error)
      return
    }

    res.sendFile(file, { root: ftpRoot, dotfiles: 'deny' })
  }

  // Express has already URL-decoded the parameter once, so a remaining '%' indicates double encoding such as %2500
  function hasAllowlistedFileType (file: string) {
    if (!file || file.includes('\0') || file.includes('%') || file.includes('\\') || path.basename(file) !== file) {
      return false
    }
    return allowlistedFileTypes.some(type => utils.endsWith(file, type))
  }

  function isPublicFile (file: string) {
    return publicFileNames.includes(file) || orderConfirmationFileName.test(file)
  }

  async function listServedFiles () {
    const entries = await fs.readdir(ftpRoot, { withFileTypes: true })
    return new Set(entries.filter(entry => entry.isFile()).map(entry => entry.name))
  }
}
