/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import * as db from '../data/mongodb'

const ftpDir = path.resolve('ftp')
const PUBLIC_FILES = ['legal.md']
const ORDER_CONFIRMATION = /^order_([0-9a-f]{4}-[0-9a-f]{16})\.pdf$/

export function authenticatedUser (req: Request) {
  const token = utils.unquote(utils.jwtFrom(req) ?? req.cookies?.token ?? '')
  if (!token || !security.verify(token)) return undefined
  const payload = security.decode(token)
  if (payload?.exp && payload.exp * 1000 < Date.now()) return undefined
  return security.authenticatedUsers.get(token) ?? (payload?.data ? { data: payload.data } : undefined)
}

export function isAdmin (req: Request) {
  return authenticatedUser(req)?.data?.role === security.roles.admin
}

async function isOrderOwner (req: Request, file: string) {
  const orderId = ORDER_CONFIRMATION.exec(file)?.[1]
  const userId = authenticatedUser(req)?.data?.id
  if (!orderId || userId === undefined) return false
  try {
    const order = await db.ordersCollection.findOne({ orderId })
    return order?.UserId !== undefined && order.UserId === userId
  } catch {
    return false
  }
}

export function denyFileAccess (req: Request, res: Response, next: NextFunction) {
  if (authenticatedUser(req)) {
    res.status(403)
    next(new Error('You are not allowed to access this file!'))
  } else {
    res.status(401)
    next(new Error('Authentication required!'))
  }
}

export function servePublicFiles () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const file = req.params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    } else if (PUBLIC_FILES.includes(file) || isAdmin(req) || await isOrderOwner(req, file)) {
      verify(file, res, next)
    } else {
      denyFileAccess(req, res, next)
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
      file = security.cutOffPoisonNullByte(file)

      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(file)

      const filePath = path.resolve(ftpDir, file)
      if (filePath.startsWith(ftpDir + path.sep)) {
        res.sendFile(filePath)
      } else {
        res.status(403)
        next(new Error('File names cannot contain forward slashes!'))
      }
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
