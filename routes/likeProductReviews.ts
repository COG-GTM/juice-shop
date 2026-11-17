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

// MarsDB runs find and modify as separate async steps, so updates to the same review are serialized here
const reviewLocks = new Map<string, Promise<unknown>>()

async function withReviewLock<T> (id: string, task: () => Promise<T>): Promise<T> {
  const previous = reviewLocks.get(id) ?? Promise.resolve()
  const current = previous.catch(() => {}).then(task)
  reviewLocks.set(id, current)
  try {
    return await current
  } finally {
    if (reviewLocks.get(id) === current) {
      reviewLocks.delete(id)
    }
  }
}

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    if (typeof id !== 'string') {
      return res.status(400).json({ error: 'Wrong Params' })
    }
    const email = user.data.email

    try {
      const result: { modified: number, updated: Review[] } = await withReviewLock(id, async () =>
        await db.reviewsCollection.update(
          { _id: id, likedBy: { $ne: email } },
          { $inc: { likesCount: 1 }, $addToSet: { likedBy: email } }
        )
      )
      if (result.modified === 0) {
        const review = await db.reviewsCollection.findOne({ _id: id })
        return review ? res.status(403).json({ error: 'Not allowed' }) : res.status(404).json({ error: 'Not found' })
      }

      challengeUtils.solveIf(challenges.timingAttackChallenge, () => result.updated[0].likedBy.filter(likedBy => likedBy === email).length > 2)
      res.json(result)
    } catch (err) {
      res.status(500).json(err)
    }
  }
}
