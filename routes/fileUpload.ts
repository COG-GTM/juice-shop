/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import crypto from 'node:crypto'
import { Readable } from 'node:stream'
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

const MAX_ZIP_ENTRIES = 100
const MAX_ZIP_UNCOMPRESSED_BYTES = 10 * 1024 * 1024

export function resolveComplaintEntryPath (entryPath: unknown): string | null {
  if (typeof entryPath !== 'string' || entryPath.length === 0 || entryPath.includes('\0')) return null
  if (path.isAbsolute(entryPath) || path.win32.isAbsolute(entryPath)) return null
  if (entryPath.split(/[\\/]/).includes('..')) return null
  const complaintsDirectory = path.resolve('uploads/complaints')
  const absolutePath = path.resolve(complaintsDirectory, entryPath)
  return absolutePath.startsWith(complaintsDirectory + path.sep) ? absolutePath : null
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const complaintsDirectory = path.resolve('uploads/complaints')
      const source = Readable.from([file.buffer])
      const parser = unzipper.Parse()
      let entryCount = 0
      let extractedBytes = 0
      let limitExceeded = false
      const stopExtraction = () => {
        limitExceeded = true
        source.unpipe(parser)
        source.destroy()
        parser.destroy()
      }
      source.pipe(parser)
        .on('entry', function (entry: any) {
          challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return path.resolve('uploads/complaints/' + entry.path) === path.resolve('ftp/legal.md') })
          if (limitExceeded) return
          if (++entryCount > MAX_ZIP_ENTRIES) {
            stopExtraction()
            return
          }
          const targetPath = entry.type === 'File' ? resolveComplaintEntryPath(entry.path) : null
          const tempPath = path.join(complaintsDirectory, `.${crypto.randomUUID()}.part`)
          let output: fs.WriteStream | null = null
          let aborted = false
          entry.on('data', function (chunk: Buffer) {
            extractedBytes += chunk.length
            if (!limitExceeded && extractedBytes > MAX_ZIP_UNCOMPRESSED_BYTES) {
              if (output !== null) {
                aborted = true
                entry.unpipe(output)
                output.destroy()
                output = null
                fs.rm(tempPath, { force: true }, () => {})
              }
              stopExtraction()
            }
          })
          if (targetPath === null) {
            entry.autodrain()
            return
          }
          output = fs.createWriteStream(tempPath, { flags: 'wx' })
            .on('error', function (err) { fs.rm(tempPath, { force: true }, () => {}); if (!aborted) next(err) })
            .on('finish', function () {
              fs.rename(tempPath, targetPath, function (err) {
                if (err != null) { fs.rm(tempPath, { force: true }, () => {}); next(err) }
              })
            })
          entry.pipe(output)
        }).on('error', function (err: unknown) { if (!limitExceeded) next(err) })
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
  handleYamlUpload
}
