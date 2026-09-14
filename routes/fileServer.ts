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
import { ordersCollection } from '../data/mongodb'

const cookieToken = (req: Request): string | undefined => {
  if (req.cookies?.token) return req.cookies.token
  const raw = req.headers.cookie?.split(';').map(cookie => cookie.trim()).find(cookie => cookie.startsWith('token='))?.slice('token='.length)
  if (!raw) return undefined
  try {
    return decodeURIComponent(raw)
  } catch {
    return raw
  }
}

const orderOwnerEmail = (req: Request): string | undefined => {
  for (const token of [cookieToken(req), utils.jwtFrom(req)]) {
    try {
      if (token && security.verify(token)) {
        const email = security.decode(token)?.data?.email
        if (email) return email
      }
    } catch {
      continue
    }
  }
  return undefined
}

export function servePublicFiles () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const file = req.params.file

    if (!file.includes('/')) {
      const effectiveFile = security.cutOffPoisonNullByte(file)
      if (effectiveFile.startsWith('order_')) {
        const email = orderOwnerEmail(req)
        if (!email) {
          res.status(401)
          next(new Error('Order confirmations can only be downloaded by logged-in customers!'))
          return
        }
        const orderId = effectiveFile.slice('order_'.length).replace(/\.pdf$/i, '')
        let order
        try {
          order = await ordersCollection.findOne({ orderId })
        } catch (error: unknown) {
          next(error instanceof Error ? error : new Error(String(error)))
          return
        }
        const ownsOrder = order != null &&
          order.email === email.replace(/[aeiou]/gi, '*') &&
          orderId.startsWith(security.hash(email).slice(0, 4) + '-')
        if (!ownsOrder) {
          res.status(403)
          next(new Error('Order confirmations can only be downloaded by the customer who placed the order!'))
          return
        }
      }
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
      file = security.cutOffPoisonNullByte(file)

      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(file)

      res.sendFile(path.resolve('ftp/', file))
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
