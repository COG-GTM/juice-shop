/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// MarsDB updates are not atomic across concurrent calls, so likes on the same review are serialized
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
      const result = await withReviewLock(id, async () => {
        const review = await db.reviewsCollection.findOne({ _id: id })
        if (!review) {
          return { status: 404 }
        }
        const update = await db.reviewsCollection.update(
          { _id: id, likedBy: { $ne: email } },
          { $inc: { likesCount: 1 }, $addToSet: { likedBy: email } }
        )
        if (update.modified === 0) {
          return { status: 403 }
        }
        return { status: 200, update }
      })

      if (result.status === 404) {
        return res.status(404).json({ error: 'Not found' })
      }
      if (result.status === 403) {
        return res.status(403).json({ error: 'Not allowed' })
      }
      res.json(result.update)
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
