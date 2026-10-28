/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import crypto from 'node:crypto'
import { Readable, Transform } from 'node:stream'
import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

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
  return targetPath.startsWith(complaintsDirectory + path.sep) && path.dirname(targetPath) === complaintsDirectory ? targetPath : null
}

const tempFileFlags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0)

function openComplaintTempFile (): { tempPath: string, fd: number } | null {
  const tempPath = path.join(complaintsDirectory, `.upload-${crypto.randomUUID()}.part`)
  try {
    if (fs.lstatSync(complaintsDirectory).isSymbolicLink()) {
      throw new Error(`${complaintsDirectory} must not be a symbolic link`)
    }
    return { tempPath, fd: fs.openSync(tempPath, tempFileFlags) }
  } catch (err) {
    logger.warn(`Could not store complaint zip entry: ${utils.getErrorMessage(err)}`)
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
    limiter: () => new Transform({
      transform (chunk: Buffer, _encoding, callback) {
        remainingBytes -= chunk.length
        callback(remainingBytes < 0 ? new Error('Zip archive exceeds the uncompressed size limit') : null, remainingBytes < 0 ? undefined : chunk)
      }
    })
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const budget = createExtractionBudget()
      const source = Readable.from([file.buffer])
      const parser = source.pipe(unzipper.Parse())
      let aborted = false
      const abort = (reason: string) => {
        if (aborted) return
        aborted = true
        logger.warn(`Aborted complaint zip extraction: ${reason}`)
        source.unpipe(parser)
        source.destroy()
        parser.destroy()
      }
      parser.on('entry', function (entry: any) {
        if (aborted) {
          entry.autodrain()
          return
        }
        const fileName = entry.path
        challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return path.resolve('uploads/complaints/' + fileName) === path.resolve('ftp/legal.md') })
        if (!budget.takeEntry()) {
          entry.autodrain()
          abort('archive exceeds the entry or size limit')
          return
        }
        const limiter = budget.limiter()
        limiter.on('error', (err: Error) => { abort(err.message) })
        const targetPath = entry.type === 'File' ? resolveComplaintEntryPath(fileName) : null
        const temp = targetPath !== null ? openComplaintTempFile() : null
        if (targetPath === null || temp === null) {
          entry.pipe(limiter).resume()
          return
        }
        const output = fs.createWriteStream(temp.tempPath, { fd: temp.fd })
        let discarded = false
        const discard = () => {
          discarded = true
          output.destroy()
          fs.rm(temp.tempPath, { force: true }, () => {})
        }
        output.on('error', (err: Error) => {
          if (discarded) return
          logger.warn(`Could not store complaint zip entry: ${err.message}`)
          limiter.unpipe(output)
          limiter.resume()
          discard()
        })
        output.on('close', () => {
          if (output.writableFinished && !discarded) {
            fs.link(temp.tempPath, targetPath, (err) => {
              if (err != null) {
                logger.warn(`Could not store complaint zip entry: ${err.message}`)
              }
              discard()
            })
          }
        })
        limiter.on('error', discard)
        entry.pipe(limiter).pipe(output)
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
