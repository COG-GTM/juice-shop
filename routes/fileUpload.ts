/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
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

const complaintsDir = path.resolve('uploads/complaints')
const maxZipEntries = 100
const maxExtractedBytes = 50 * 1024 * 1024

function resolveComplaintPath (fileName: string) {
  if (path.isAbsolute(fileName) || fileName.split(/[/\\]/).includes('..')) {
    return null
  }
  const target = path.resolve(complaintsDir, fileName)
  if (!isInside(complaintsDir, target)) {
    return null
  }
  try {
    if (!isInside(realPath(complaintsDir), realPath(existingAncestor(target)))) { // a symlinked sub-directory would otherwise redirect the write
      return null
    }
    if (fs.lstatSync(target, { throwIfNoEntry: false })?.isSymbolicLink() === true) {
      return null
    }
  } catch {
    return null
  }
  return target
}

function isInside (baseDir: string, target: string) {
  const relative = path.relative(baseDir, target)
  return relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative)
}

function existingAncestor (target: string) {
  let dir = path.dirname(target)
  while (!fs.existsSync(dir) && path.dirname(dir) !== dir) {
    dir = path.dirname(dir)
  }
  return dir
}

function realPath (dir: string) {
  return fs.existsSync(dir) ? fs.realpathSync(dir) : dir
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
            let entryCount = 0
            let extractedBytes = 0
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return path.resolve('uploads/complaints/' + fileName) === path.resolve('ftp/legal.md') })
                const target = resolveComplaintPath(fileName)
                entryCount++
                if (target === null || entry.type === 'Directory' || entryCount > maxZipEntries || extractedBytes > maxExtractedBytes) {
                  entry.autodrain()
                } else {
                  try {
                    fs.mkdirSync(path.dirname(target), { recursive: true })
                  } catch {
                    entry.autodrain()
                    return
                  }
                  const writeStream = fs.createWriteStream(target).on('error', function (err) { next(err) })
                  entry.on('data', function (chunk: Buffer) {
                    extractedBytes += chunk.length
                    if (extractedBytes > maxExtractedBytes) {
                      entry.unpipe(writeStream)
                      writeStream.destroy()
                      fs.rm(target, { force: true }, function () {})
                      entry.autodrain()
                    }
                  })
                  entry.pipe(writeStream)
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
  resolveComplaintPath,
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
