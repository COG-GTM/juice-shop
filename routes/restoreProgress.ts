/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import Hashids from 'hashids/cjs'
import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'

const hashidsAlphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
const hashidRegexp = /^([a-zA-Z0-9]+)(?:\.([a-f0-9]{64}))?$/
const invalidContinueCode = 'Invalid continue code.'

export function restoreProgress () {
  return ({ params }: Request, res: Response) => {
    const hashids = new Hashids('this is my salt', 60, hashidsAlphabet)
    const match = hashidRegexp.exec(params.continueCode)
    if (match === null) {
      return res.status(404).send(invalidContinueCode)
    }
    const [, continueCode, signature] = match
    const ids = hashids.decode(continueCode)
    if (challengeUtils.notSolved(challenges.continueCodeChallenge) && ids.includes(999)) {
      challengeUtils.solve(challenges.continueCodeChallenge)
      res.end()
    } else if (ids.length > 0 && security.verifyContinueCode('continueCode', continueCode, signature)) {
      for (const challenge of Object.values(challenges)) {
        if (ids.includes(challenge.id)) {
          challengeUtils.solve(challenge, true)
        }
      }
      res.json({ data: ids.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send(invalidContinueCode)
    }
  }
}

export function restoreProgressFindIt () {
  return async ({ params }: Request, res: Response) => {
    const hashids = new Hashids('this is the salt for findIt challenges', 60, hashidsAlphabet)
    const match = hashidRegexp.exec(params.continueCode)
    if (match === null) {
      return res.status(404).send(invalidContinueCode)
    }
    const [, continueCodeFindIt, signature] = match
    const idsFindIt = hashids.decode(continueCodeFindIt)
    if (idsFindIt.length > 0 && security.verifyContinueCode('continueCodeFindIt', continueCodeFindIt, signature)) {
      for (const challenge of Object.values(challenges)) {
        if (idsFindIt.includes(challenge.id)) {
          await challengeUtils.solveFindIt(challenge.key, true)
        }
      }
      res.json({ data: idsFindIt.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send(invalidContinueCode)
    }
  }
}

export function restoreProgressFixIt () {
  const hashids = new Hashids('yet another salt for the fixIt challenges', 60, hashidsAlphabet)
  return async ({ params }: Request, res: Response) => {
    const match = hashidRegexp.exec(params.continueCode)
    if (match === null) {
      return res.status(404).send(invalidContinueCode)
    }
    const [, continueCodeFixIt, signature] = match
    const idsFixIt = hashids.decode(continueCodeFixIt)
    if (idsFixIt.length > 0 && security.verifyContinueCode('continueCodeFixIt', continueCodeFixIt, signature)) {
      for (const challenge of Object.values(challenges)) {
        if (idsFixIt.includes(challenge.id)) {
          await challengeUtils.solveFixIt(challenge.key, true)
        }
      }
      res.json({ data: idsFixIt.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send(invalidContinueCode)
    }
  }
}
