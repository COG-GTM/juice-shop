/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from 'data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'
import { UserModel } from '../models/user'

// Blocking sleep function as in native MongoDB
// @ts-expect-error FIXME Type safety broken for global object
global.sleep = (time: number) => {
  // Ensure that users don't accidentally dos their servers for too long
  if (time > 2000) {
    time = 2000
  }
  const stop = new Date().getTime()
  while (new Date().getTime() < stop + time) {
    ;
  }
}

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Truncate id to avoid unintentional RCE
    const id = !utils.isChallengeEnabled(challenges.noSqlCommandChallenge) ? Number(req.params.id) : utils.trunc(req.params.id, 40)

    // Measure how long the query takes, to check if there was a nosql dos attack
    const t0 = new Date().getTime()

    db.reviewsCollection.find({ $where: 'this.product == ' + id }).then(async (reviews: Review[]) => {
      try {
        const t1 = new Date().getTime()
        challengeUtils.solveIf(challenges.noSqlCommandChallenge, () => { return (t1 - t0) > 2000 })
        const user = security.authenticatedUsers.from(req)
        const authors = [...new Set(reviews.map(review => review.author))]
        const authorUsers = await UserModel.findAll({ where: { email: authors }, attributes: ['email', 'username'] })
        const usernames = new Map(authorUsers.map(authorUser => [authorUser.email, authorUser.username]))
        const publicReviews = reviews.map(({ _id, product, message, author, likesCount, likedBy }) => ({
          _id,
          product,
          message,
          author: displayName(author, usernames.get(author)),
          likesCount,
          liked: user === undefined || likedBy.includes(user.data.email) ? true : undefined,
          editable: user !== undefined && author !== 'Anonymous' && author === user.data.email ? true : undefined
        }))
        res.json(utils.queryResultToJson(publicReviews))
      } catch (err) {
        next(err)
      }
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}

function displayName (author: string, username?: string) {
  if (author === 'Anonymous') return author
  return username && !username.includes('@') ? username : 'Customer'
}
