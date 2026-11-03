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

const xmlToken = /<\?[\s\S]*?(?:\?>|$)|<!--[\s\S]*?(?:-->|$)|<!\[CDATA\[[\s\S]*?(?:\]\]>|$)|<!ENTITY\s+(%\s+)?([^\s%>"']+)\s+(SYSTEM\s+|PUBLIC\s+(?:"[^"]*"|'[^']*')\s+)?("[^"]*"|'[^']*')[^>]*>?|<![a-z][^>"'[]*(?:(?:"[^"]*"?|'[^']*'?)[^>"'[]*)*(\[?)|(\])|<[a-z_:][^>"']*(?:(?:"[^"]*"?|'[^']*'?)[^>"']*)*>?|([&%])([^\s;&%#<>"'[\]]+);/gi
const fileDisclosureTarget = /^file:\/\/\/?(?:etc\/passwd|[a-z]:\/windows\/system\.ini)$/i
const devRandomTarget = /^file:\/\/\/?dev\/u?random$/i
const maxParameterEntityDepth = 8

function parseXmlWithoutEntities (data: string) {
  const sandbox = { libxml, data }
  vm.createContext(sandbox)
  return vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: false, nonet: true, dtdload: false, dtdattr: false, dtdvalid: false, nocdata: true })', sandbox, { timeout: 2000 })
}

function contentReferences (text: string) {
  const references: string[] = []
  for (const [, , , , , , , referenceType, referenceName] of text.matchAll(xmlToken)) {
    if (referenceType === '&') references.push('&' + referenceName)
  }
  return references
}

function reachableExternalEntities (data: string) {
  const declarations = new Map<string, { external: boolean, value: string }>()
  const expandedParameters = new Set<string>()
  const pending: string[] = []
  let doctypeEnd = -1
  const scan = (text: string, inSubset: boolean, depth: number) => {
    let inInternalSubset = inSubset
    for (const match of text.matchAll(xmlToken)) {
      const [, parameter, name, externalId, literal, subsetStart, subsetEnd, referenceType, referenceName] = match
      if (name !== undefined) {
        const key = (parameter !== undefined ? '%' : '&') + name
        if (!declarations.has(key)) declarations.set(key, { external: externalId !== undefined, value: literal.slice(1, -1) })
      } else if (subsetStart === '[') {
        inInternalSubset = true
      } else if (subsetEnd !== undefined) {
        if (depth === 0 && inInternalSubset && doctypeEnd < 0) doctypeEnd = text.indexOf('>', match.index)
        inInternalSubset = false
      } else if (referenceName !== undefined && inInternalSubset && referenceType === '%') {
        const key = '%' + referenceName
        const declaration = declarations.get(key)
        if (declaration?.external === false) {
          if (depth < maxParameterEntityDepth && !expandedParameters.has(key)) {
            expandedParameters.add(key)
            scan(declaration.value, true, depth + 1)
          }
        } else {
          pending.push(key)
        }
      } else if (referenceName !== undefined && !inInternalSubset && referenceType === '&') {
        pending.push('&' + referenceName)
      }
    }
  }
  scan(data, false, 0)
  if (!isWellFormedWithoutDtd(data, doctypeEnd, declarations)) return []
  const visited = new Set<string>()
  const externalTargets: string[] = []
  while (pending.length > 0) {
    const key = pending.pop() as string
    const declaration = declarations.get(key)
    if (visited.has(key) || declaration === undefined) continue
    visited.add(key)
    if (declaration.external) {
      externalTargets.push(declaration.value)
    } else {
      pending.push(...contentReferences(declaration.value))
    }
  }
  return externalTargets
}

function isWellFormedWithoutDtd (data: string, doctypeEnd: number, declarations: Map<string, unknown>) {
  if (doctypeEnd < 0) return false
  const body = data.slice(doctypeEnd + 1).replace(/&([^\s;&%#<>"'[\]]+);/g, (reference: string, name: string) => declarations.has('&' + name) ? '' : reference)
  if (containsDtd(body)) return false
  try {
    parseXmlWithoutEntities(body)
    return true
  } catch {
    return false
  }
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.xxeFileDisclosureChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      const data = file.buffer.toString()
      if (containsDtd(data)) {
        const externalTargets = reachableExternalEntities(data)
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return externalTargets.some(target => fileDisclosureTarget.test(target)) })
        if (externalTargets.some(target => devRandomTarget.test(target))) {
          challengeUtils.solveIf(challenges.xxeDosChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: XML documents must not contain a DTD (' + file.originalname + ')'))
        }
      } else {
        try {
          const xmlDoc = parseXmlWithoutEntities(data)
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

const MAX_YAML_UPLOAD_BYTES = 100000
const MAX_YAML_JSON_LENGTH = 1000000
const MAX_YAML_ALIAS_EXPANSION = 1000
const YAML_ALIAS_LIMIT_ERROR = 'YAML document contains too many aliases'

// Aborts parsing once aliases have dereferenced more than `limit` nodes in total, each alias costing one
// plus the entries of the collection it points to. This bounds the parser's own work for merge keys
// (`<<: *a`), which copy the aliased mapping on every use. js-yaml closes alias nodes without a `kind`
// (nested block contexts close the same alias twice at the same position).
function yamlAliasLimiter (limit = MAX_YAML_ALIAS_EXPANSION) {
  let expansion = 0
  let lastAliasEnd = -1
  return (eventType: string, state: { kind: string | null, result: unknown, position: number }) => {
    if (eventType === 'close' && state.kind === null && state.result != null && state.position !== lastAliasEnd) {
      lastAliasEnd = state.position
      expansion += 1 + (typeof state.result === 'object' ? Object.keys(state.result).length : 0)
      if (expansion > limit) {
        throw new Error(YAML_ALIAS_LIMIT_ERROR)
      }
    }
  }
}

// Estimates the length of JSON.stringify(value) without building the string. Aliased nodes are
// shared references in the parsed document, so each object's (and string's) size is computed once and
// reused at every reference; the walk stays linear in the parsed graph while still accounting for the
// exponential expansion that serialization would materialize. Every node is visited (no early exit), so
// cyclic aliases always throw like JSON.stringify, even in documents that are also oversized.
function estimateJsonLength (value: unknown, sizes = new Map<unknown, number>()): number {
  if (value === null || (typeof value !== 'object' && typeof value !== 'string')) { return String(value).length }
  const known = sizes.get(value)
  if (known === -1) { throw new TypeError('Converting circular structure to JSON') }
  if (known !== undefined) { return known }
  if (typeof value === 'string') {
    const length = JSON.stringify(value).length
    sizes.set(value, length)
    return length
  }
  sizes.set(value, -1)
  let length = 2
  if (typeof (value as { toJSON?: unknown }).toJSON === 'function') {
    length = estimateJsonLength((value as { toJSON: () => unknown }).toJSON(), sizes)
  } else {
    for (const [key, child] of Object.entries(value)) {
      length += (Array.isArray(value) ? 1 : JSON.stringify(key).length + 2) + estimateJsonLength(child, sizes)
    }
  }
  sizes.set(value, length)
  return length
}

function solveYamlBombChallenge (res: Response, next: NextFunction) {
  if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
    challengeUtils.solve(challenges.yamlBombChallenge)
  }
  res.status(503)
  next(new Error('Sorry, we are temporarily not available! Please try again later.'))
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      if (file.buffer.length > MAX_YAML_UPLOAD_BYTES) {
        res.status(413)
        next(new Error('File is too large to be processed (' + file.originalname + ')'))
      } else {
        const data = file.buffer.toString()
        try {
          const sandbox = { yaml, data, listener: yamlAliasLimiter() }
          vm.createContext(sandbox)
          const parsedYaml = vm.runInContext('yaml.load(data, { listener })', sandbox, { timeout: 2000 })
          if (estimateJsonLength(parsedYaml) > MAX_YAML_JSON_LENGTH) {
            solveYamlBombChallenge(res, next)
          } else {
            res.status(410)
            next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(JSON.stringify(parsedYaml), 400) + ' (' + file.originalname + ')'))
          }
        } catch (err: unknown) {
          const errorMessage = err instanceof Error ? err.message : String(err)
          if (utils.contains(errorMessage, 'Invalid string length') || utils.contains(errorMessage, 'Script execution timed out') || errorMessage === YAML_ALIAS_LIMIT_ERROR) {
            solveYamlBombChallenge(res, next)
          } else {
            res.status(410)
            next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
          }
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
  estimateJsonLength,
  yamlAliasLimiter
}
