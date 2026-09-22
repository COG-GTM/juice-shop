/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import { reviewsCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

function authorFrom (req: Request) {
  const user = security.authenticatedUsers.from(req)
  if (user?.data?.email) {
    return user.data.email
  }
  const token = utils.jwtFrom(req)
  if (token && security.verify(token)) {
    return (security.decode(token) as { data?: { email?: string } } | undefined)?.data?.email
  }
}

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const author = authorFrom(req)
    if (!author) {
      return res.status(401).json({ error: 'Unauthenticated' })
    }

    try {
      await reviewsCollection.insert({
        product: req.params.id,
        message: req.body.message,
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
