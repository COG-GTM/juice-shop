/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { chargeCard, debitWallet, PaymentError } from '../lib/payment'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const membershipCost = 49

export function upgradeToDeluxe () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = await UserModel.findOne({ where: { id: req.body.UserId, role: security.roles.customer } })
      if (user == null) {
        res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' })
        return
      }
      const { paymentMode, paymentId } = req.body
      if (paymentMode !== 'wallet' && paymentMode !== 'card') {
        res.status(400).json({ status: 'error', error: 'Invalid payment mode' })
        return
      }
      if (UserModel.sequelize == null) {
        throw new Error('Database is not initialized')
      }

      let updatedUser: UserModel
      try {
        updatedUser = await UserModel.sequelize.transaction(async (transaction) => {
          if (paymentMode === 'wallet') {
            await debitWallet(user.id, membershipCost, transaction)
          } else {
            await chargeCard(user.id, paymentId, membershipCost)
          }
          return await user.update({ role: security.roles.deluxe, deluxeToken: security.deluxeToken(user.email) }, { transaction })
        })
      } catch (error: unknown) {
        if (error instanceof PaymentError) {
          res.status(400).json({ status: 'error', error: error.reason === 'insufficientFunds' ? 'Insuffienct funds in Wallet' : 'Invalid Card' })
        } else {
          res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' })
        }
        return
      }

      const userWithStatus = utils.queryResultToJson(updatedUser)
      const updatedToken = security.authorize(userWithStatus)
      security.authenticatedUsers.put(updatedToken, userWithStatus)
      res.status(200).json({ status: 'success', data: { confirmation: 'Congratulations! You are now a deluxe member!', token: updatedToken } })
    } catch (err: unknown) {
      res.status(400).json({ status: 'error', error: 'Something went wrong: ' + utils.getErrorMessage(err) })
    }
  }
}

export function deluxeMembershipStatus () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (security.isCustomer(req)) {
      res.status(200).json({ status: 'success', data: { membershipCost } })
    } else if (security.isDeluxe(req)) {
      res.status(400).json({ status: 'error', error: 'You are already a deluxe member!' })
    } else {
      res.status(400).json({ status: 'error', error: 'You are not eligible for deluxe membership!' })
    }
  }
}
