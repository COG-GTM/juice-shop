/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import Hashids from 'hashids/cjs'

import logger from './logger'
import { getErrorMessage } from './utils'

export type ContinueCodeKind = 'continueCode' | 'findIt' | 'fixIt'

const hashidsAlphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
const hashids: Record<ContinueCodeKind, Hashids> = {
  continueCode: new Hashids('this is my salt', 60, hashidsAlphabet),
  findIt: new Hashids('this is the salt for findIt challenges', 60, hashidsAlphabet),
  fixIt: new Hashids('yet another salt for the fixIt challenges', 60, hashidsAlphabet)
}
const continueCodeRegexp = /^[a-zA-Z0-9]+$/
const signatureLength = 64
const keyFile = path.resolve('data', 'continueCode.key')

let cachedKey: string | undefined
const getKey = () => {
  if (cachedKey) return cachedKey
  if (process.env.CONTINUE_CODE_KEY) {
    cachedKey = process.env.CONTINUE_CODE_KEY
    return cachedKey
  }
  try {
    cachedKey = fs.readFileSync(keyFile, 'utf8').trim()
  } catch {}
  if (!cachedKey) {
    cachedKey = crypto.randomBytes(32).toString('hex')
    try {
      fs.writeFileSync(keyFile, cachedKey, { mode: 0o600, flag: 'wx' })
    } catch (err) {
      logger.warn('Could not persist continue code key to ' + keyFile + ' (' + getErrorMessage(err) + '); continue codes will not survive a restart')
    }
  }
  return cachedKey
}

const sign = (kind: ContinueCodeKind, payload: string) => crypto.createHmac('sha256', getKey()).update(kind + ':' + payload).digest('hex')

export const encodeContinueCode = (kind: ContinueCodeKind, ids: number[]) => {
  const payload = hashids[kind].encode(ids)
  return payload + sign(kind, payload)
}

export const decodeContinueCode = (kind: ContinueCodeKind, code: string) => {
  if (!continueCodeRegexp.test(code) || code.length <= signatureLength) return []
  const payload = code.slice(0, -signatureLength)
  const signature = Buffer.from(code.slice(-signatureLength))
  const expected = Buffer.from(sign(kind, payload))
  if (!crypto.timingSafeEqual(signature, expected)) return []
  return hashids[kind].decode(payload)
}

export const decodeUnsignedContinueCode = (code: string) => {
  if (!continueCodeRegexp.test(code)) return []
  return hashids.continueCode.decode(code)
}
