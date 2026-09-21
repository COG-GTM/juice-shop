/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export const getRecycleItem = () => (req: Request, res: Response) => {
  const id = Number(req.params.id)
  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).send({ error: 'Invalid recycle id.' })
  }
  const token = utils.jwtFrom(req)
  const decodedToken = security.verify(token) ? security.decode(token) : null
  const userId = decodedToken?.data?.id
  if (!userId) {
    return res.status(401).send({ error: 'Authentication required.' })
  }
  RecycleModel.findAll({
    where: {
      id,
      UserId: userId
    }
  }).then((Recycle) => {
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
