/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { ValidationError } from 'sequelize'
import { AddressModel } from '../models/address'

export function getAddress () {
  return async (req: Request, res: Response) => {
    const addresses = await AddressModel.findAll({ where: { UserId: req.body.UserId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

export function getAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

export function updateAddressById () {
  return async (req: Request, res: Response) => {
    const where = { id: req.params.id, UserId: req.body.UserId }
    let updated: number
    try {
      [updated] = await AddressModel.update(req.body, {
        where,
        fields: ['fullName', 'mobileNum', 'zipCode', 'streetAddress', 'city', 'state', 'country']
      })
    } catch (error) {
      if (error instanceof ValidationError) {
        res.status(400).json({ message: 'Validation error', errors: error.errors.map(({ message, path }) => ({ message, field: path })) })
        return
      }
      throw error
    }
    const address = updated > 0 ? await AddressModel.findOne({ where }) : null
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}
