/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      const review = await db.reviewsCollection.findOne({ _id: id })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      if (review.likedBy.includes(user.data.email)) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      // Single conditional update so the "one like per user" check and the write cannot interleave
      const result = await db.reviewsCollection.update(
        { _id: id, likedBy: { $ne: user.data.email } },
        {
          $inc: { likesCount: 1 },
          $push: { likedBy: user.data.email }
        }
      )

      res.json(result)
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
