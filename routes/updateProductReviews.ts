/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const { id, message } = req.body

    if (typeof id !== 'string' || typeof message !== 'string') {
      return res.status(400).json({ error: 'Invalid input' })
    }
    if (!user?.data?.email) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      const review = await db.reviewsCollection.findOne({ _id: id })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }
      if (review.author !== user.data.email) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      const result: { modified: number, original: Array<{ author: any }> } = await db.reviewsCollection.update(
        { _id: id, author: user.data.email },
        { $set: { message } }
      )
      challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 }) // vuln-code-snippet hide-line
      challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 }) // vuln-code-snippet hide-line
      res.json(result)
    } catch (err: unknown) {
      res.status(500).json(err)
    }
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
