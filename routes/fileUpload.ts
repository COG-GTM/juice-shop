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
import { Transform } from 'node:stream'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const MAX_COMPLAINT_BYTES = 200000
const MAX_ZIP_ENTRIES = 100
const MAX_ZIP_ENTRY_BYTES = 1000000
const MAX_ZIP_TOTAL_BYTES = 5000000
const MAX_XML_EXPANDED_BYTES = 1000000
const MAX_YAML_EXPANDED_NODES = 200000

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

// Aborts decompression of a zip entry once it or the archive as a whole exceeds the allowed
// amount of decompressed data, so that a small archive cannot expand into a huge disk write.
function decompressionLimiter (budget: { remaining: number }) {
  let written = 0
  return new Transform({
    transform (chunk: Buffer, _encoding, callback) {
      written += chunk.length
      budget.remaining -= chunk.length
      if (written > MAX_ZIP_ENTRY_BYTES || budget.remaining < 0) {
        callback(new Error('Decompressed zip content exceeds the allowed size'))
        return
      }
      callback(null, chunk)
    }
  })
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
            const budget = { remaining: MAX_ZIP_TOTAL_BYTES }
            let entries = 0
            const parser = unzipper.Parse()
            fs.createReadStream(tempFile)
              .pipe(parser)
              .on('entry', function (entry: any) {
                entries++
                if (entries > MAX_ZIP_ENTRIES) {
                  entry.autodrain()
                  parser.destroy(new Error('Zip archive contains too many entries'))
                  return
                }
                const fileName = entry.path
                const absolutePath = path.resolve('uploads/complaints/' + fileName)
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
                if (absolutePath.includes(path.resolve('.'))) {
                  entry
                    .pipe(decompressionLimiter(budget).on('error', function (err: unknown) {
                      entry.autodrain()
                      next(err)
                    }))
                    .pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err) }))
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

// Determines how many characters the internal entities of an XML document expand into, which is
// what entity bombs blow up. Entities are only measured once and their size reused, so the walk
// stays linear in the number of declarations even for exponential expansion.
function expandedEntitySize (name: string, declarations: Map<string, string>, sizes: Map<string, number>): number {
  const known = sizes.get(name)
  if (known !== undefined) { return known }
  const value = declarations.get(name)
  if (value === undefined) { return name.length + 2 }
  sizes.set(name, Number.POSITIVE_INFINITY) // recursive entities cannot be expanded at all
  const size = expandedSize(value, declarations, sizes)
  sizes.set(name, size)
  return size
}

function expandedSize (text: string, declarations: Map<string, string>, sizes: Map<string, number>): number {
  let size = text.length
  for (const reference of text.matchAll(/&([^&;\s]+);/g)) {
    size += expandedEntitySize(reference[1], declarations, sizes)
    if (size > MAX_XML_EXPANDED_BYTES) { return Number.POSITIVE_INFINITY }
  }
  return size
}

function exceedsEntityExpansionLimit (data: string) {
  const declarations = new Map<string, string>()
  for (const declaration of data.matchAll(/<!ENTITY\s+(?:%\s+)?([^\s%<>]+)\s+(?:"([^"]*)"|'([^']*)')\s*>/g)) {
    declarations.set(declaration[1], declaration[2] ?? declaration[3] ?? '')
  }
  if (declarations.size === 0) { return false }
  return expandedSize(data, declarations, new Map<string, number>()) > MAX_XML_EXPANDED_BYTES
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
      if (exceedsEntityExpansionLimit(file.buffer.toString())) {
        if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
          challengeUtils.solve(challenges.xxeDosChallenge)
        }
        res.status(503)
        next(new Error('Sorry, we are temporarily not available! Please try again later.'))
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

// Counts the nodes a parsed YAML document has once its aliases are resolved, which is what
// serializing it materializes. Shared nodes are only walked once and their size reused, so the
// walk stays linear in the parsed graph even when aliases expand exponentially.
function expandedNodeCount (value: unknown, sizes = new Map<object, number>()): number {
  if (value === null || typeof value !== 'object') { return 1 }
  const known = sizes.get(value)
  if (known !== undefined) { return known }
  sizes.set(value, Number.POSITIVE_INFINITY) // cyclic aliases cannot be serialized at all
  let nodes = 1
  for (const child of Object.values(value)) {
    nodes += expandedNodeCount(child, sizes)
    if (nodes > MAX_YAML_EXPANDED_NODES) { break }
  }
  sizes.set(value, nodes)
  return nodes
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
        if (expandedNodeCount(parsedYaml) > MAX_YAML_EXPANDED_NODES) {
          if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
            challengeUtils.solve(challenges.yamlBombChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
          return
        }
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(JSON.stringify(parsedYaml), 400) + ' (' + file.originalname + ')'))
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
  expandedNodeCount,
  exceedsEntityExpansionLimit
}
