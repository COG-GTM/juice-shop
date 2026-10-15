/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'

// MarsDB runs find, modify and persist of an update as separate async steps,
// so likes are serialized to make the conditional update below atomic.
let likeQueue: Promise<unknown> = Promise.resolve()
const serializeLike = async <T>(task: () => Promise<T>): Promise<T> => {
  const run = likeQueue.then(task, task)
  likeQueue = run.catch(() => {})
  return await run
}

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    const email = user.data.email
    if (typeof id !== 'string' || typeof email !== 'string') {
      return res.status(400).json({ error: 'Wrong Params' })
    }

    try {
      const review = await db.reviewsCollection.findOne({ _id: id })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      const result = await serializeLike(async () => await db.reviewsCollection.update(
        { _id: id, likedBy: { $ne: email } },
        { $inc: { likesCount: 1 }, $addToSet: { likedBy: email } }
      ))
      if (result.modified === 0) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      const updatedReview: Review = result.updated[0]
      const count = updatedReview.likedBy.filter(likedByEmail => likedByEmail === email).length
      challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

      res.json(result)
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
