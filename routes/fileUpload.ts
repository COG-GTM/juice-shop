/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'
import { parseInSandbox } from '../lib/sandboxedParser'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
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
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                const absolutePath = path.resolve('uploads/complaints/' + fileName)
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
                if (absolutePath.includes(path.resolve('.'))) {
                  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err) }))
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

function deprecatedUploadError (file: Express.Multer.File | undefined, details?: string) {
  return new Error('B2B customer complaints via file upload have been deprecated for security reasons' + (details !== undefined ? ': ' + details : '') + ' (' + file?.originalname + ')')
}

function temporarilyUnavailableError () {
  return new Error('Sorry, we are temporarily not available! Please try again later.')
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (!utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    next()
    return
  }
  challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
  if (file?.buffer == null || !(utils.isChallengeEnabled(challenges.xxeFileDisclosureChallenge) || utils.isChallengeEnabled(challenges.xxeDosChallenge))) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
    res.status(410)
    next(deprecatedUploadError(file))
    return
  }
  parseInSandbox('xml', file.buffer.toString(), { substituteEntities: utils.isChallengeEnabled(challenges.xxeFileDisclosureChallenge) }).then(({ status, output = '', message = '', disclosesFile = false }) => {
    if (status === 'ok') {
      challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return disclosesFile })
      res.status(410)
      next(deprecatedUploadError(file, utils.trunc(output, 400)))
    } else if (status === 'error') {
      res.status(410)
      next(deprecatedUploadError(file, message))
    } else {
      if (status !== 'busy') {
        challengeUtils.solveIf(challenges.xxeDosChallenge, () => { return true })
      }
      res.status(503)
      next(temporarilyUnavailableError())
    }
  }).catch(next)
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (!(utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml'))) {
    res.status(204).end()
    return
  }
  challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
  if (file?.buffer == null || !utils.isChallengeEnabled(challenges.yamlBombChallenge)) {
    res.status(410)
    next(deprecatedUploadError(file))
    return
  }
  parseInSandbox('yaml', file.buffer.toString()).then(({ status, output = '', message = '' }) => {
    if (status === 'ok') {
      res.status(410)
      next(deprecatedUploadError(file, utils.trunc(output, 400)))
    } else if (status === 'error') {
      res.status(410)
      next(deprecatedUploadError(file, message))
    } else {
      if (status !== 'busy') {
        challengeUtils.solveIf(challenges.yamlBombChallenge, () => { return true })
      }
      res.status(503)
      next(temporarilyUnavailableError())
    }
  }).catch(next)
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
