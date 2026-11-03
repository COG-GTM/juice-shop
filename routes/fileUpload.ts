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

function containsDtd (data: string) {
  return /<!(DOCTYPE|ENTITY)/i.test(data)
}

const externalFileEntity = (target: string) => new RegExp(`(<!--[\\s\\S]*?(?:-->|$)|<!\\[CDATA\\[[\\s\\S]*?(?:\\]\\]>|$))|<!ENTITY\\s+(%\\s+)?([^\\s%>"']+)\\s+(?:SYSTEM|PUBLIC\\s+(?:"[^"]*"|'[^']*'))\\s+["']file:///?(?:${target})["']|<![a-z][^>"'[]*(?:(?:"[^"]*(?:"|$)|'[^']*(?:'|$))[^>"'[]*)*`, 'gi')
const fileDisclosureEntity = externalFileEntity('etc/passwd|[a-z]:/windows/system\\.ini')
const devRandomEntity = externalFileEntity('dev/u?random')

function usesExternalEntity (data: string, entity: RegExp) {
  const references: string[] = []
  let text = ''
  let pos = 0
  let lastDeclarationEnd = 0
  for (const match of data.matchAll(entity)) {
    const index = match.index ?? 0
    if (match[1] != null) {
      text += data.slice(pos, index) + ' '.repeat(match[0].length)
      pos = index + match[0].length
    } else {
      lastDeclarationEnd = index + match[0].length
      if (match[3] != null) references.push((match[2] != null ? '%' : '&') + match[3] + ';')
    }
  }
  text += data.slice(pos)
  const subsetEnd = text.indexOf(']', lastDeclarationEnd)
  const dtd = subsetEnd === -1 ? text : text.slice(0, subsetEnd)
  return references.some(reference => (reference.startsWith('%') ? dtd : text).includes(reference))
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.xxeFileDisclosureChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      const data = file.buffer.toString()
      if (containsDtd(data)) {
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return usesExternalEntity(data, fileDisclosureEntity) })
        if (usesExternalEntity(data, devRandomEntity)) {
          challengeUtils.solveIf(challenges.xxeDosChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: XML documents must not contain a DTD (' + file.originalname + ')'))
        }
      } else {
        try {
          const sandbox = { libxml, data }
          vm.createContext(sandbox)
          const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: false, nonet: true, dtdload: false, dtdattr: false, dtdvalid: false, nocdata: true })', sandbox, { timeout: 2000 })
          res.status(410)
          if (xmlDoc.getDtd() != null) {
            next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: XML documents must not contain a DTD (' + file.originalname + ')'))
          } else {
            next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file.originalname + ')'))
          }
        } catch {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: invalid XML document (' + file.originalname + ')'))
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
