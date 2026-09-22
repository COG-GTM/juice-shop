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

export function putAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address != null) {
      const { id, UserId, ...updatableAttributes } = req.body
      try {
        const updatedAddress = await address.update(updatableAttributes)
        res.status(200).json({ status: 'success', data: updatedAddress })
      } catch (error: unknown) {
        if (error instanceof ValidationError) {
          res.status(400).json({
            message: error.message,
            errors: error.errors.map(({ path, message }) => ({ field: path, message }))
          })
        } else {
          throw error
        }
      }
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
