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
  const data = security.authenticatedUsers.from(req)?.data ?? (req as Request & { user?: { data?: { id?: number, email?: string } } }).user?.data
  if (data?.id != null && data.email && await UserModel.findOne({ where: { id: data.id, email: data.email } })) {
    return data.email
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
