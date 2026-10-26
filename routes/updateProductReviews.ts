/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    if (!user?.data?.email) {
      res.status(401).send()
      return
    }
    if (typeof req.body.id !== 'string' || typeof req.body.message !== 'string') { // vuln-code-snippet vuln-line noSqlReviewsChallenge
      res.status(400).send()
      return
    }
    db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
      { _id: req.body.id, author: user.data.email }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        if (result.modified === 0) {
          res.status(403).send()
          return
        }
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
