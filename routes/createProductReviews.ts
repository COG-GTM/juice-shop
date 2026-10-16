/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { rateLimit } from 'express-rate-limit'

import { reviewsCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const MAX_REVIEW_LENGTH = 160

type RequestWithJwtUser = Request & { user?: { data?: { email?: string } } }

const reviewAuthorOf = (req: Request) => security.authenticatedUsers.from(req) ?? (req as RequestWithJwtUser).user

export const reviewCreationRateLimit = () => rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  keyGenerator: (req: Request) => reviewAuthorOf(req)?.data?.email ?? req.ip ?? '',
  validate: false
})

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const user = reviewAuthorOf(req)
    if (!user?.data?.email) {
      return res.status(401).json({ status: 'error', message: 'Unauthorized' })
    }

    const message = req.body?.message
    if (typeof message !== 'string' || message.trim().length === 0 || message.length > MAX_REVIEW_LENGTH) {
      return res.status(400).json({ status: 'error', message: `Review message must be a non-empty string of at most ${MAX_REVIEW_LENGTH} characters` })
    }

    try {
      await reviewsCollection.insert({
        product: req.params.id,
        message,
        author: user.data.email,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
