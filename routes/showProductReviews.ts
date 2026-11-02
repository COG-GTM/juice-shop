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

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    challengeUtils.solveIf(challenges.noSqlCommandChallenge, () => { return /sleep\(\s*\d+\s*\)/.test(req.params.id) })

    const id = Number(req.params.id)
    if (!Number.isFinite(id)) {
      res.status(400).json({ error: 'Wrong Params' })
      return
    }

    db.reviewsCollection.find({ product: { $in: [id, String(id)] } }).then((reviews: Review[]) => {
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
