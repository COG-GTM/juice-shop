/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'
import { AddressModel } from '../models/address'

import * as utils from '../lib/utils'

export const getRecycleItem = () => (req: Request, res: Response) => {
  RecycleModel.findAll({
    where: {
      id: JSON.parse(req.params.id),
      UserId: req.body.UserId
    }
  }).then((Recycle) => {
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

export const checkRecycleAddressOwnership = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body?.AddressId == null) {
      next()
      return
    }
    const address = await AddressModel.findByPk(req.body.AddressId)
    if (address == null || address.UserId !== req.body.UserId) {
      res.status(403).json({ status: 'error', error: 'AddressId does not belong to the authenticated user.' })
      return
    }
    next()
  }
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
