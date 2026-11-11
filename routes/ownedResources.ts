/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { type Model, type ModelStatic } from 'sequelize'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

type OwnedModel = ModelStatic<Model & { UserId?: number | null }>

const parseId = (id: string) => /^\d+$/.test(id) ? Number(id) : undefined

export const listOwned = (model: OwnedModel) => async (req: Request, res: Response) => {
  const records = await model.findAll({ where: { UserId: req.body.UserId } })
  res.json(utils.queryResultToJson(records))
}

export const getOwnedById = (model: OwnedModel) => async (req: Request, res: Response) => {
  const id = parseId(req.params.id)
  if (id === undefined) {
    res.status(400).json({ status: 'error', message: 'Invalid id' })
    return
  }
  const records = await model.findAll({ where: { id, UserId: req.body.UserId } })
  res.json(utils.queryResultToJson(records))
}

export const restrictToOwnerOrAdmin = (model: OwnedModel) => async (req: Request, res: Response, next: NextFunction) => {
  const user = security.authenticatedUsers.from(req)?.data
  if (!user) {
    res.status(401).json({ status: 'error', message: 'Unauthorized' })
    return
  }
  const id = parseId(req.params.id)
  const record = id !== undefined ? await model.findByPk(id) : null
  if (record == null) {
    res.status(404).json({ status: 'error', message: 'Not found' })
    return
  }
  if (user.role === security.roles.admin || record.UserId === user.id) {
    next()
  } else {
    res.status(403).json({ status: 'error', message: 'Malicious activity detected' })
  }
}
