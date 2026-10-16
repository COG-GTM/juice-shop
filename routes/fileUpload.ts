/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import crypto from 'node:crypto'
import { Transform } from 'node:stream'
import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

const complaintsDirectory = path.resolve('uploads/complaints')

function resolveComplaintEntryPath (entryPath: unknown): string | null {
  if (typeof entryPath !== 'string' || entryPath.length === 0 || entryPath.includes('\0')) {
    return null
  }
  const segments = entryPath.split(/[\\/]/)
  if (path.posix.isAbsolute(entryPath) || path.win32.isAbsolute(entryPath) || /^[a-zA-Z]:/.test(entryPath) || segments.includes('..')) {
    return null
  }
  const targetPath = path.resolve(complaintsDirectory, ...segments)
  return path.dirname(targetPath) === complaintsDirectory ? targetPath : null
}

const tempFileFlags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0)

function openComplaintTempFile (): { tempPath: string, fd: number } | null {
  const tempPath = path.join(complaintsDirectory, `.upload-${crypto.randomUUID()}.part`)
  try {
    return { tempPath, fd: fs.openSync(tempPath, tempFileFlags) }
  } catch {
    return null
  }
}

const maxComplaintZipEntries = 100
const maxComplaintZipUncompressedBytes = 10 * 1024 * 1024

function createExtractionBudget () {
  let remainingEntries = maxComplaintZipEntries
  let remainingBytes = maxComplaintZipUncompressedBytes
  return {
    takeEntry: () => remainingEntries-- > 0 && remainingBytes > 0,
    limiter: () => {
      let exceeded = false
      return new Transform({
        transform (chunk: Buffer, _encoding, callback) {
          remainingBytes -= chunk.length
          if (remainingBytes < 0) exceeded = true
          callback(null, exceeded ? undefined : chunk)
        },
        flush (callback) {
          callback(exceeded ? new Error('Zip archive exceeds the uncompressed size limit') : null)
        }
      })
    }
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const buffer = file.buffer
      const filename = file.originalname.toLowerCase()
      const tempFile = path.join(os.tmpdir(), filename)
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err) }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            const budget = createExtractionBudget()
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return path.resolve('uploads/complaints/' + fileName) === path.resolve('ftp/legal.md') })
                const targetPath = entry.type === 'File' ? resolveComplaintEntryPath(fileName) : null
                const temp = targetPath !== null && budget.takeEntry() ? openComplaintTempFile() : null
                if (targetPath !== null && temp !== null) {
                  const limiter = budget.limiter()
                  const output = fs.createWriteStream(temp.tempPath, { fd: temp.fd })
                  const discard = () => { fs.rm(temp.tempPath, { force: true }, () => {}) }
                  output.on('error', () => { limiter.unpipe(output); limiter.resume(); discard() })
                  output.on('close', () => {
                    if (output.writableFinished) fs.rename(temp.tempPath, targetPath, (err) => { if (err != null) discard() })
                  })
                  limiter.on('error', () => { output.destroy(); discard() })
                  entry.pipe(limiter).pipe(output)
                } else {
                  entry.autodrain()
                }
              }).on('error', function (err: unknown) { next(err) })
          })
        })
      })
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

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip' || fileType === 'yml' || fileType === 'yaml')
  })
  next()
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      const data = file.buffer.toString()
      try {
        const sandbox = { libxml, data }
        vm.createContext(sandbox)
        const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })
        const xmlString = xmlDoc.toString(false)
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)) })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        if (utils.contains(errorMessage, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
            challengeUtils.solve(challenges.xxeDosChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      const data = file.buffer.toString()
      try {
        const sandbox = { yaml, data }
        vm.createContext(sandbox)
        const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(yamlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        if (utils.contains(errorMessage, 'Invalid string length') || utils.contains(errorMessage, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
            challengeUtils.solve(challenges.yamlBombChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload,
  resolveComplaintEntryPath,
  createExtractionBudget
}
