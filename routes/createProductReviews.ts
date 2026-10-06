/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import { reviewsCollection } from '../data/mongodb'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

async function authenticatedEmail (req: Request): Promise<string | undefined> {
  const user = security.authenticatedUsers.from(req)
  if (user?.data?.email) {
    return user.data.email
  }
  const token = utils.jwtFrom(req)
  if (token && security.verify(token)) {
    const email = (security.decode(token) as { data?: { email?: string } } | undefined)?.data?.email
    if (email && await UserModel.findOne({ where: { email } })) {
      return email
    }
  }
}

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const author = await authenticatedEmail(req)
    if (!author) {
      return res.status(401).json({ status: 'error', message: 'Unauthorized' })
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
