/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { Readable } from 'node:stream'
import fileType from 'file-type'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const allowedFileTypes = ['pdf', 'zip']
const deprecatedFileTypes = ['xml', 'yml', 'yaml']

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

function resolveComplaintEntryPath (entryPath: string) {
  if (typeof entryPath !== 'string' || entryPath.length === 0 || entryPath.includes('\0') || path.isAbsolute(entryPath)) {
    return null
  }
  const complaintsDir = path.resolve('uploads/complaints')
  const targetPath = path.resolve(complaintsDir, entryPath)
  return targetPath.startsWith(complaintsDir + path.sep) ? targetPath : null
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      Readable.from(file.buffer)
        .pipe(unzipper.Parse())
        .on('entry', function (entry: any) {
          const targetPath = entry.type === 'File' ? resolveComplaintEntryPath(entry.path) : null
          if (targetPath != null) {
            fs.mkdirSync(path.dirname(targetPath), { recursive: true })
            entry.pipe(fs.createWriteStream(targetPath).on('error', function (err) { next(err) }))
          } else {
            entry.autodrain()
          }
        }).on('error', function (err: unknown) { next(err) })
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

async function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const extension = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase() ?? ''
  if (deprecatedFileTypes.includes(extension)) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    return res.status(410).json({ error: 'B2B customer complaints via file upload have been deprecated for security reasons' })
  }
  try {
    const detectedType = file?.buffer != null ? await fileType.fromBuffer(file.buffer) : undefined
    if (allowedFileTypes.includes(extension) && detectedType?.ext === extension) {
      next()
    } else {
      return res.status(415).json({ error: 'Only PDF and ZIP files are allowed' })
    }
  } catch (err: unknown) {
    next(err)
  }
}

function handleFileUploadSuccess (req: Request, res: Response) {
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleFileUploadSuccess
}
