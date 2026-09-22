/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const getRecycleItem = () => (req: Request, res: Response) => {
  const id = Number.parseInt(req.params.id, 10)
  if (!Number.isInteger(id) || String(id) !== req.params.id.trim()) {
    res.status(400).json({ error: 'Invalid recycle id' })
    return
  }

  const user = security.authenticatedUsers.from(req)
  if (!user?.data?.id) {
    res.status(401).json({ error: 'Unauthorized' })
    return
  }

  RecycleModel.findAll({
    where: {
      id,
      UserId: user.data.id
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
