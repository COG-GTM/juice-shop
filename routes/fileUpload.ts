/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import unzipper from 'unzipper'
import { Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const MAX_COMPLAINT_BYTES = 200000
const MAX_ZIP_ENTRIES = 100
const MAX_ZIP_ENTRY_BYTES = 1000000
const MAX_ZIP_TOTAL_BYTES = 5000000
const MAX_YAML_EXPANDED_BYTES = 1000000

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

class DecompressionLimitError extends Error {}

// Aborts an entry once it or the archive as a whole decompresses into more data than allowed,
// so that a small archive cannot expand into an arbitrarily large disk write.
function decompressionLimiter (budget: { remaining: number }) {
  let written = 0
  return new Transform({
    transform (chunk: Buffer, _encoding, callback) {
      written += chunk.length
      budget.remaining -= chunk.length
      if (written > MAX_ZIP_ENTRY_BYTES || budget.remaining < 0) {
        callback(new DecompressionLimitError('Decompressed zip content exceeds the allowed size'))
        return
      }
      callback(null, chunk)
    }
  })
}

async function extractZipBuffer (buffer: Buffer) {
  const directory = await unzipper.Open.buffer(buffer)
  if (directory.files.length > MAX_ZIP_ENTRIES) {
    throw new DecompressionLimitError('Zip archive contains too many entries')
  }
  const budget = { remaining: MAX_ZIP_TOTAL_BYTES }
  for (const entry of directory.files) {
    const fileName = entry.path
    const absolutePath = path.resolve('uploads/complaints/' + fileName)
    challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
    if (absolutePath.includes(path.resolve('.'))) {
      const target = 'uploads/complaints/' + fileName
      try {
        await pipeline(entry.stream(), decompressionLimiter(budget), fs.createWriteStream(target))
      } catch (err: unknown) {
        fs.rmSync(target, { force: true }) // a rejected entry must not leave a partially written file behind
        throw err
      }
    }
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      extractZipBuffer(file.buffer).then(() => {
        res.status(204).end()
      }).catch((err: unknown) => {
        if (err instanceof DecompressionLimitError) {
          res.status(413)
          next(err)
        } else {
          res.status(204).end()
        }
      })
      return
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
      if (file.buffer.length > MAX_COMPLAINT_BYTES) {
        res.status(413)
        next(new Error('File is too large to be processed (' + file.originalname + ')'))
        return
      }
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

// Determines how many characters serializing a parsed YAML document materializes. Shared nodes
// are measured once and their size reused, so the walk stays linear in the parsed graph even
// when its aliases expand exponentially.
function expandedYamlSize (value: unknown, sizes = new Map<object, number>()): number {
  if (value === null || value === undefined) { return 4 }
  if (typeof value !== 'object') { return String(value).length }
  const known = sizes.get(value)
  if (known !== undefined) { return known }
  sizes.set(value, Number.POSITIVE_INFINITY) // cyclic aliases cannot be serialized at all
  let size = 2
  for (const [key, child] of Object.entries(value)) {
    size += key.length + expandedYamlSize(child, sizes) + 4
    if (size > MAX_YAML_EXPANDED_BYTES) { break }
  }
  sizes.set(value, size)
  return size
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      if (file.buffer.length > MAX_COMPLAINT_BYTES) {
        res.status(413)
        next(new Error('File is too large to be processed (' + file.originalname + ')'))
        return
      }
      const data = file.buffer.toString()
      try {
        const sandbox = { yaml, data }
        vm.createContext(sandbox)
        const parsedYaml = vm.runInContext('yaml.load(data)', sandbox, { timeout: 2000 })
        if (expandedYamlSize(parsedYaml) > MAX_YAML_EXPANDED_BYTES) {
          if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
            challengeUtils.solve(challenges.yamlBombChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
          return
        }
        const yamlString = JSON.stringify(parsedYaml)
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
  expandedYamlSize,
  decompressionLimiter,
  extractZipBuffer,
  DecompressionLimitError
}
