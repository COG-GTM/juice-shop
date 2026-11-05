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
const stagingFileName = /^\.upload-.*\.part$/i

function resolveComplaintEntryPath (entryPath: unknown): string | null {
  if (typeof entryPath !== 'string' || entryPath.length === 0 || entryPath.includes('\0')) {
    return null
  }
  const segments = entryPath.split(/[\\/]/)
  if (path.posix.isAbsolute(entryPath) || path.win32.isAbsolute(entryPath) || /^[a-zA-Z]:/.test(entryPath) || segments.includes('..')) {
    return null
  }
  const targetPath = path.resolve(complaintsDirectory, ...segments)
  if (stagingFileName.test(path.basename(targetPath))) {
    return null
  }
  return targetPath.startsWith(complaintsDirectory + path.sep) && path.dirname(targetPath) === complaintsDirectory ? targetPath : null
}

const tempFileFlags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0)

function isReachableWithoutSymlinks (directory: string): boolean {
  const appRoot = path.dirname(path.dirname(directory))
  return fs.realpathSync(directory) === path.join(fs.realpathSync(appRoot), path.relative(appRoot, directory))
}

function complaintsDirectoryIsSafe (): boolean {
  try {
    return isReachableWithoutSymlinks(complaintsDirectory)
  } catch (err) {
    logger.warn(`Could not verify ${complaintsDirectory}: ${utils.getErrorMessage(err)}`)
    return false
  }
}

function openComplaintTempFile (): { tempPath: string, fd: number } | null {
  const tempPath = path.join(complaintsDirectory, `.upload-${crypto.randomUUID()}.part`)
  try {
    if (!complaintsDirectoryIsSafe()) {
      throw new Error(`${complaintsDirectory} must not be reached through a symbolic link`)
    }
    return { tempPath, fd: fs.openSync(tempPath, tempFileFlags) }
  } catch (err) {
    logger.warn(`Could not store complaint zip entry: ${utils.getErrorMessage(err)}`)
    return null
  }
}

const maxComplaintZipEntries = 100
const maxComplaintZipUncompressedBytes = 10 * 1024 * 1024
const complaintZipLimitError = `Zip archive exceeds the limit of ${maxComplaintZipEntries} entries or ${maxComplaintZipUncompressedBytes / (1024 * 1024)} MB uncompressed`

function createExtractionBudget () {
  let remainingEntries = maxComplaintZipEntries
  let remainingBytes = maxComplaintZipUncompressedBytes
  return {
    takeEntry: () => remainingEntries-- > 0 && remainingBytes >= 0,
    limiter: () => new Transform({
      transform (chunk: Buffer, _encoding, callback) {
        remainingBytes -= chunk.length
        callback(remainingBytes < 0 ? new Error('Zip archive exceeds the uncompressed size limit') : null, remainingBytes < 0 ? undefined : chunk)
      }
    })
  }
}

const complaintStoreError = 'Could not store the attached ZIP archive'

interface StagedComplaintEntry { tempPath: string, targetPath: string }

function targetIsNotRegularFile (targetPath: string): boolean {
  try {
    return !fs.lstatSync(targetPath).isFile()
  } catch (err: any) {
    return err?.code !== 'ENOENT'
  }
}

const renameAsync = async (from: string, to: string) => { await fs.promises.rename(from, to) }
const removeQuietly = async (file: string) => { await fs.promises.rm(file, { force: true }).catch(() => {}) }

const restoreBackup = async (backupPath: string, targetPath: string) => {
  await renameAsync(backupPath, targetPath).catch(err => {
    logger.warn(`Could not restore ${targetPath}, original content kept in ${backupPath}: ${utils.getErrorMessage(err)}`)
  })
}

async function publishEntries (entries: StagedComplaintEntry[], isAborted: () => boolean): Promise<boolean> {
  const done: Array<{ targetPath: string, backupPath: string | null }> = []
  let failed = false
  for (const entry of entries) {
    if (isAborted() || !complaintsDirectoryIsSafe()) { failed = true; break }
    let backupPath: string | null = null
    try {
      if (fs.existsSync(entry.targetPath)) {
        backupPath = path.join(complaintsDirectory, `.upload-${crypto.randomUUID()}.part`)
        await renameAsync(entry.targetPath, backupPath)
      }
      await renameAsync(entry.tempPath, entry.targetPath)
      done.push({ targetPath: entry.targetPath, backupPath })
    } catch (err) {
      logger.warn(`Could not store complaint zip entry: ${utils.getErrorMessage(err)}`)
      if (backupPath !== null && !fs.existsSync(entry.targetPath)) await restoreBackup(backupPath, entry.targetPath)
      failed = true
      break
    }
  }
  if (failed) {
    for (const { targetPath, backupPath } of done.reverse()) {
      if (backupPath !== null) await restoreBackup(backupPath, targetPath)
      else await removeQuietly(targetPath)
    }
    await Promise.all(entries.map(async entry => { await removeQuietly(entry.tempPath) }))
    return false
  }
  await Promise.all(done.map(async ({ backupPath }) => { if (backupPath !== null) await removeQuietly(backupPath) }))
  return true
}

let publication: Promise<unknown> = Promise.resolve()

async function publishAtomically (entries: StagedComplaintEntry[], isAborted: () => boolean): Promise<boolean> {
  const result = publication.then(async () => await publishEntries(entries, isAborted))
  publication = result.catch(() => {})
  return await result
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const budget = createExtractionBudget()
      const source = Readable.from([file.buffer])
      const parser = source.pipe(unzipper.Parse())
      const staged: Array<Promise<StagedComplaintEntry | null>> = []
      const activeDiscards = new Set<() => void>()
      let aborted = false
      let finalized = false
      let responded = false
      let storeFailed = false
      let encryptedEntrySeen = false
      const respond = (status: number, error?: string) => {
        if (responded) return
        responded = true
        if (error === undefined) res.status(status).end()
        else res.status(status).json({ error })
      }
      const removeStaged = (entries: Array<StagedComplaintEntry | null>) => {
        entries.forEach(entry => { if (entry !== null) fs.rm(entry.tempPath, { force: true }, () => {}) })
      }
      const abort = (reason: string, status: number, error?: string) => {
        if (aborted) return
        aborted = true
        logger.warn(`Aborted complaint zip extraction: ${reason}`)
        respond(status, error)
        activeDiscards.forEach(discard => { discard() })
        source.unpipe(parser)
        source.destroy()
        parser.destroy()
        void Promise.all(staged).then(removeStaged)
      }
      const publish = () => {
        if (finalized) return
        finalized = true
        void Promise.all(staged).then(results => {
          const entries = results.filter((entry): entry is StagedComplaintEntry => entry !== null)
          if (aborted) {
            removeStaged(entries)
            return
          }
          if (storeFailed || !complaintsDirectoryIsSafe()) {
            removeStaged(entries)
            respond(500, complaintStoreError)
            return
          }
          if (entries.some(entry => targetIsNotRegularFile(entry.targetPath))) {
            removeStaged(entries)
            respond(500, complaintStoreError)
            return
          }
          void publishAtomically(entries, () => aborted).then(published => {
            if (published) respond(204)
            else if (!aborted) respond(500, complaintStoreError)
          })
        })
      }
      parser.on('finish', () => { setImmediate(publish) })
      parser.on('close', () => { setImmediate(publish) })
      parser.on('entry', function (entry: any) {
        if (aborted || finalized) {
          entry.autodrain()
          return
        }
        const fileName = entry.path
        challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return path.resolve('uploads/complaints/' + fileName) === path.resolve('ftp/legal.md') })
        if (!budget.takeEntry()) {
          entry.autodrain()
          abort('archive exceeds the entry or size limit', 413, complaintZipLimitError)
          return
        }
        const limiter = budget.limiter()
        limiter.on('error', (err: Error) => { abort(err.message, 413, complaintZipLimitError) })
        const encrypted = ((entry.vars?.flags ?? 0) & 0x01) !== 0
        if (encrypted) encryptedEntrySeen = true
        const targetPath = entry.type === 'File' && !encrypted ? resolveComplaintEntryPath(fileName) : null
        const temp = targetPath !== null ? openComplaintTempFile() : null
        if (targetPath === null || temp === null) {
          if (targetPath !== null) storeFailed = true
          entry.pipe(limiter).resume()
          return
        }
        const output = fs.createWriteStream(temp.tempPath, { fd: temp.fd })
        let discarded = false
        const discard = () => {
          if (discarded) return
          discarded = true
          const removeTemp = () => { fs.rm(temp.tempPath, { force: true }, () => {}) }
          if (output.closed) removeTemp()
          else output.once('close', removeTemp)
          output.destroy()
        }
        activeDiscards.add(discard)
        staged.push(new Promise(resolve => {
          output.on('close', () => {
            activeDiscards.delete(discard)
            resolve(output.writableFinished && !discarded ? { tempPath: temp.tempPath, targetPath } : null)
          })
        }))
        output.on('error', (err: Error) => {
          if (discarded) return
          logger.warn(`Could not store complaint zip entry: ${err.message}`)
          storeFailed = true
          limiter.unpipe(output)
          limiter.resume()
          discard()
        })
        limiter.on('error', discard)
        entry.pipe(limiter).pipe(output)
      }).on('error', function (err: unknown) {
        if (encryptedEntrySeen) abort(`encrypted entry: ${utils.getErrorMessage(err)}`, 204)
        else abort(utils.getErrorMessage(err), 400, 'Invalid ZIP archive')
      })
    } else {
      res.status(204).end()
    }
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

function localFilePath (systemId: string) {
  const match = /^file:\/\/(?:localhost)?(\/[^?#]*)$/i.exec(systemId)
  if (match == null) return null
  try {
    return path.posix.normalize(decodeURIComponent(match[1]))
  } catch {
    return null
  }
}

function isFileDisclosureTarget (systemId: string) {
  const file = localFilePath(systemId)
  return file != null && (file === '/etc/passwd' || /^\/[a-z]:\/windows\/system\.ini$/i.test(file))
}

function isDevRandomTarget (systemId: string) {
  const file = localFilePath(systemId)
  return file === '/dev/random' || file === '/dev/urandom'
}
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

function referencesExternalEntity (key: string, declarations: Map<string, { external: boolean, value: string }>) {
  const pending = [key]
  const visited = new Set<string>()
  while (pending.length > 0) {
    const current = pending.pop() as string
    const declaration = declarations.get(current)
    if (declaration === undefined || visited.has(current)) continue
    if (declaration.external) return true
    visited.add(current)
    for (const [, name] of declaration.value.matchAll(/&([^\s;&%#<>"'[\]]+);/g)) pending.push('&' + name)
  }
  return false
}

const entityReferenceAt = /&([^\s;&%#<>"'[\]]+);/y

function stripDeclaredReferences (text: string, declarations: Map<string, { external: boolean, value: string }>) {
  const externalReferences = new Map<string, boolean>()
  const isExternal = (key: string) => {
    if (!externalReferences.has(key)) externalReferences.set(key, referencesExternalEntity(key, declarations))
    return externalReferences.get(key) === true
  }
  let result = ''
  let index = 0
  while (index < text.length) {
    const character = text[index]
    if (character === '&') {
      entityReferenceAt.lastIndex = index
      const reference = entityReferenceAt.exec(text)
      if (reference !== null) {
        if (!declarations.has('&' + reference[1])) result += reference[0]
        index += reference[0].length
        continue
      }
    } else if (character === '<') {
      const closer = text.startsWith('<!--', index) ? '-->' : text.startsWith('<![CDATA[', index) ? ']]>' : text.startsWith('<?', index) ? '?>' : null
      if (closer !== null) {
        const closerIndex = text.indexOf(closer, index)
        if (closerIndex < 0) return result + text.slice(index)
        result += text.slice(index, closerIndex + closer.length)
        index = closerIndex + closer.length
        continue
      }
      let tagEnd = index + 1
      let quote: string | null = null
      while (tagEnd < text.length && (quote !== null || text[tagEnd] !== '>')) {
        if (quote === null && (text[tagEnd] === '"' || text[tagEnd] === "'")) quote = text[tagEnd]
        else if (text[tagEnd] === quote) quote = null
        tagEnd++
      }
      if (tagEnd >= text.length) return result + text.slice(index)
      result += text.slice(index, tagEnd + 1).replace(/&([^\s;&%#<>"'[\]]+);/g, (reference: string, name: string) => declarations.has('&' + name) && !isExternal('&' + name) ? '' : reference)
      index = tagEnd + 1
      continue
    }
    result += character
    index++
  }
  return result
}

function withoutCommentsCdataAndPis (text: string) {
  let result = ''
  let index = 0
  while (index < text.length) {
    const start = text.indexOf('<', index)
    if (start < 0) break
    const closer = text.startsWith('<!--', start) ? '-->' : text.startsWith('<![CDATA[', start) ? ']]>' : text.startsWith('<?', start) ? '?>' : null
    if (closer === null) {
      result += text.slice(index, start + 1)
      index = start + 1
      continue
    }
    result += text.slice(index, start)
    const closerIndex = text.indexOf(closer, start)
    if (closerIndex < 0) return result
    index = closerIndex + closer.length
  }
  return result + text.slice(index)
}

function isWellFormedWithoutExpansion (data: string, doctypeEnd: number, declarations: Map<string, { external: boolean, value: string }>) {
  if (doctypeEnd < 0) return false
  const body = stripDeclaredReferences(data.slice(doctypeEnd + 1), declarations)
  if (containsDtd(withoutCommentsCdataAndPis(body))) return false
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
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return externalTargets.some(isFileDisclosureTarget) })
        if (externalTargets.some(isDevRandomTarget)) {
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
  isReachableWithoutSymlinks,
  publishAtomically,
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload,
  resolveComplaintEntryPath,
  createExtractionBudget
}
