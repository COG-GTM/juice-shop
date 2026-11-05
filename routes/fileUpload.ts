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
const maxParameterEntityDepth = 40

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
  if (!isWellFormedWithoutExpansion(data, doctypeEnd, declarations)) return []
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
      for (const reference of contentReferences(declaration.value)) pending.push(reference)
    }
  }
  return externalTargets
}

function referencesExternalEntity (key: string, declarations: Map<string, { external: boolean, value: string }>, visited = new Set<string>()): boolean {
  const declaration = declarations.get(key)
  if (declaration === undefined || visited.has(key)) return false
  if (declaration.external) return true
  visited.add(key)
  return [...declaration.value.matchAll(/&([^\s;&%#<>"'[\]]+);/g)].some(([, name]) => referencesExternalEntity('&' + name, declarations, visited))
}

function isWellFormedWithoutExpansion (data: string, doctypeEnd: number, declarations: Map<string, { external: boolean, value: string }>) {
  if (doctypeEnd < 0) return false
  const entityReference = /&([^\s;&%#<>"'[\]]+);/g
  const body = data.slice(doctypeEnd + 1).replace(/<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<\?[\s\S]*?\?>|<[^>"']*(?:(?:"[^"]*"|'[^']*')[^>"']*)*>|&([^\s;&%#<>"'[\]]+);/g, (token: string, name?: string) => {
    if (name !== undefined) return declarations.has('&' + name) ? '' : token
    if (!token.startsWith('<') || /^<[!?]/.test(token)) return token
    return token.replace(entityReference, (reference: string, attributeName: string) => declarations.has('&' + attributeName) && !referencesExternalEntity('&' + attributeName, declarations) ? '' : reference)
  })
  if (containsDtd(body)) return false
  try {
    parseXmlWithoutEntities(body)
    parseXmlWithoutEntities(data.slice(0, doctypeEnd + 1) + body)
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
