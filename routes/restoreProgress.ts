/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { decodeContinueCode, decodeUnsignedContinueCode } from '../lib/continueCode'

const invalidContinueCode = 'Invalid continue code.'

export function restoreProgress () {
  return ({ params }: Request, res: Response) => {
    const continueCode = params.continueCode
    if (challengeUtils.notSolved(challenges.continueCodeChallenge) && decodeUnsignedContinueCode(continueCode).includes(999)) {
      challengeUtils.solve(challenges.continueCodeChallenge)
      return res.end()
    }
    const ids = decodeContinueCode('continueCode', continueCode)
    if (ids.length > 0) {
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
    const idsFindIt = decodeContinueCode('findIt', params.continueCode)
    if (idsFindIt.length > 0) {
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
  return async ({ params }: Request, res: Response) => {
    const idsFixIt = decodeContinueCode('fixIt', params.continueCode)
    if (idsFixIt.length > 0) {
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
