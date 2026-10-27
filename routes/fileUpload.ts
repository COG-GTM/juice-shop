/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { Readable } from 'node:stream'
import { spawn } from 'node:child_process'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const PARSER_TIMEOUT_MS = 2000
const PARSER_MEMORY_LIMIT_MB = 64
const MAX_CONCURRENT_PARSERS = 2
const PARSER_PREVIEW_LENGTH = 401
const PARSER_TIMEOUT_MESSAGE = 'Script execution timed out'
const PARSER_EXHAUSTED_MESSAGE = 'Parser ran out of memory'

let activeParsers = 0

// Parsing happens in a throwaway process so that neither a never-ending external entity
// nor an alias bomb can block the single event loop: the process is hard-killed on timeout
const parserScript = `
const chunks = []
process.stdin.on('data', (chunk) => chunks.push(chunk))
process.stdin.on('end', () => {
  const [type, modulePath, previewLength, disclosurePatterns] = process.argv.slice(1)
  const data = Buffer.concat(chunks).toString()
  try {
    const parsed = type === 'xml'
      ? require(modulePath).parseXml(data, { noblanks: true, noent: true, nocdata: true }).toString(false)
      : String(JSON.stringify(require(modulePath).safeLoad(data)))
    const fileDisclosed = JSON.parse(disclosurePatterns).some(({ source, flags }) => new RegExp(source, flags).test(parsed))
    process.stdout.write(JSON.stringify({ preview: parsed.slice(0, Number(previewLength)), fileDisclosed }))
  } catch (err) {
    process.stderr.write(String(err?.message ?? err))
    process.exitCode = 1
  }
})
`

function isMemoryExhaustion (errorOutput: string, signal: NodeJS.Signals | null) {
  return signal != null || errorOutput.includes('heap out of memory') || errorOutput.includes('Invalid string length')
}

const fileDisclosurePatterns = JSON.stringify([utils.etcPasswdFilePattern, utils.systemIniFilePattern].map(({ source, flags }) => ({ source, flags })))

function parseInSeparateProcess (type: 'xml' | 'yaml', data: string) {
  return new Promise<{ preview: string, fileDisclosed: boolean }>((resolve, reject) => {
    const modulePath = require.resolve(type === 'xml' ? 'libxmljs2' : 'js-yaml')
    const parser = spawn(process.execPath, ['--max-old-space-size=' + PARSER_MEMORY_LIMIT_MB, '-e', parserScript, type, modulePath, String(PARSER_PREVIEW_LENGTH), type === 'xml' ? fileDisclosurePatterns : '[]'])
    activeParsers++
    let output = ''
    let errorOutput = ''
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      parser.kill('SIGKILL')
    }, PARSER_TIMEOUT_MS)
    parser.stdout.on('data', (chunk) => { output += chunk })
    parser.stderr.on('data', (chunk) => { errorOutput += chunk })
    parser.stdin.on('error', () => { /* parser gone, handled via close */ })
    parser.on('error', (err) => {
      clearTimeout(timer)
      activeParsers--
      reject(err)
    })
    parser.on('close', (code, signal) => {
      clearTimeout(timer)
      activeParsers--
      if (timedOut) {
        reject(new Error(PARSER_TIMEOUT_MESSAGE))
      } else if (isMemoryExhaustion(errorOutput, signal)) {
        reject(new Error(PARSER_EXHAUSTED_MESSAGE))
      } else if (code === 0) {
        try {
          resolve(JSON.parse(output))
        } catch (err) {
          reject(err)
        }
      } else {
        reject(new Error(utils.trunc(errorOutput, 200) || 'Parser exited with code ' + code))
      }
    })
    parser.stdin.end(data)
  })
}

function isResourceExhaustionError (err: unknown) {
  const errorMessage = err instanceof Error ? err.message : String(err)
  return errorMessage === PARSER_TIMEOUT_MESSAGE || errorMessage === PARSER_EXHAUSTED_MESSAGE
}

function deprecationError (fileName: string, details?: string) {
  return new Error('B2B customer complaints via file upload have been deprecated for security reasons' + (details != null ? ': ' + details : '') + ' (' + fileName + ')')
}

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
      Readable.from(file.buffer)
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
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.xxeFileDisclosureChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      if (activeParsers >= MAX_CONCURRENT_PARSERS) {
        res.status(503)
        next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        return
      }
      const fileName = file.originalname
      parseInSeparateProcess('xml', file.buffer.toString()).then(({ preview, fileDisclosed }) => {
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return fileDisclosed })
        res.status(410)
        next(deprecationError(fileName, utils.trunc(preview, 400)))
      }, (err: unknown) => {
        if (isResourceExhaustionError(err)) {
          challengeUtils.solveIf(challenges.xxeDosChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(deprecationError(fileName, err instanceof Error ? err.message : String(err)))
        }
      })
      return
    }
    res.status(410)
    next(deprecationError(String(file?.originalname)))
    return
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.yamlBombChallenge)) {
      if (activeParsers >= MAX_CONCURRENT_PARSERS) {
        res.status(503)
        next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        return
      }
      const fileName = file.originalname
      parseInSeparateProcess('yaml', file.buffer.toString()).then(({ preview }) => {
        res.status(410)
        next(deprecationError(fileName, utils.trunc(preview, 400)))
      }, (err: unknown) => {
        if (isResourceExhaustionError(err)) {
          challengeUtils.solveIf(challenges.yamlBombChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(deprecationError(fileName, err instanceof Error ? err.message : String(err)))
        }
      })
      return
    }
    res.status(410)
    next(deprecationError(String(file?.originalname)))
    return
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
