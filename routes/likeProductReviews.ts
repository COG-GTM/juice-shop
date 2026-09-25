/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'

interface LikeOutcome {
  status: number
  body: unknown
}

const pendingLikes = new Map<string, Promise<unknown>>()

// Serializes the like-once check and the write per review to avoid a TOCTOU race
const serializePerReview = async (id: string, task: () => Promise<LikeOutcome>): Promise<LikeOutcome> => {
  const current = (pendingLikes.get(id) ?? Promise.resolve()).then(task)
  const settled = current.catch(() => undefined)
  pendingLikes.set(id, settled)
  try {
    return await current
  } finally {
    if (pendingLikes.get(id) === settled) {
      pendingLikes.delete(id)
    }
  }
}

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    if (typeof id !== 'string') {
      return res.status(400).json({ error: 'Wrong Params' })
    }
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      const { status, body } = await serializePerReview(id, async () => {
        const review: Review = await db.reviewsCollection.findOne({ _id: id })
        if (!review) {
          return { status: 404, body: { error: 'Not found' } }
        }

        const likedBy = review.likedBy
        if (likedBy.includes(user.data.email)) {
          return { status: 403, body: { error: 'Not allowed' } }
        }

        const result = await db.reviewsCollection.update(
          { _id: id },
          { $inc: { likesCount: 1 }, $set: { likedBy: [...likedBy, user.data.email] } }
        )
        return { status: 200, body: result }
      })
      res.status(status).json(body)
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
