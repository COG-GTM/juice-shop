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

export function updateAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address == null) {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
      return
    }
    try {
      await address.update(req.body, { fields: ['fullName', 'mobileNum', 'zipCode', 'streetAddress', 'city', 'state', 'country'] })
      res.status(200).json({ status: 'success', data: address })
    } catch (error: unknown) {
      if (error instanceof ValidationError) {
        res.status(400).json({ message: error.message, errors: error.errors.map(({ message, type, path, value }) => ({ message, type, path, value })) })
      } else {
        throw error
      }
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
