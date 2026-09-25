/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from 'data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'

const SLEEP_COMMAND = /^sleep\((\d+)\)$/
const MAX_SLEEP = 2000
const DOS_THRESHOLD = 1000

export function showProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = Number(req.params.id)

    // Delays the response like a NoSQL sleep command would, without evaluating any user input
    const sleepCommand = SLEEP_COMMAND.exec(req.params.id)
    if (sleepCommand && utils.isChallengeEnabled(challenges.noSqlCommandChallenge)) {
      const delay = Math.min(Number(sleepCommand[1]), MAX_SLEEP)
      await new Promise((resolve) => setTimeout(resolve, delay))
      challengeUtils.solveIf(challenges.noSqlCommandChallenge, () => delay >= DOS_THRESHOLD)
    }

    db.reviewsCollection.find({ product: id }).then((reviews: Review[]) => {
      const user = security.authenticatedUsers.from(req)
      for (let i = 0; i < reviews.length; i++) {
        if (user === undefined || reviews[i].likedBy.includes(user.data.email)) {
          reviews[i].liked = true
        }
      }
      res.json(utils.queryResultToJson(reviews))
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}
