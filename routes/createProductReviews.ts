/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import { reviewsCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const MAX_REVIEW_LENGTH = 160

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const author = security.authenticatedUsers.from(req)?.data?.email
    if (!author) {
      return res.status(401).json({ status: 'error', message: 'Unauthorized' })
    }
    if (!/^\d+$/.test(req.params.id)) {
      return res.status(400).json({ status: 'error', message: 'Invalid product id' })
    }
    const message = req.body?.message
    if (typeof message !== 'string' || message.trim().length === 0 || message.length > MAX_REVIEW_LENGTH) {
      return res.status(400).json({ status: 'error', message: `Review must be between 1 and ${MAX_REVIEW_LENGTH} characters` })
    }

    try {
      await reviewsCollection.insert({
        product: req.params.id,
        message,
        author,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
