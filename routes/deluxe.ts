/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { literal, Op } from 'sequelize'

import { WalletModel } from '../models/wallet'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import { CardModel } from '../models/card'
import * as utils from '../lib/utils'

const deluxeMembershipCost = 49
const supportedPaymentModes = ['wallet', 'card']

class UpgradeError extends Error {}

export function upgradeToDeluxe () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = await UserModel.findOne({ where: { id: req.body.UserId, role: security.roles.customer } })
      if (user == null) {
        res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' })
        return
      }
      if (!supportedPaymentModes.includes(req.body.paymentMode)) {
        res.status(400).json({ status: 'error', error: 'Invalid payment mode' })
        return
      }

      if (req.body.paymentMode === 'card') {
        const card = await CardModel.findOne({ where: { id: req.body.paymentId, UserId: req.body.UserId } })
        if ((card == null) || card.expYear < new Date().getFullYear() || (card.expYear === new Date().getFullYear() && card.expMonth - 1 < new Date().getMonth())) {
          res.status(400).json({ status: 'error', error: 'Invalid Card' })
          return
        }
      }

      try {
        const updatedUser = await UserModel.sequelize?.transaction(async (transaction) => {
          if (req.body.paymentMode === 'wallet') {
            const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId }, transaction })
            if (wallet == null) {
              throw new UpgradeError('Insuffienct funds in Wallet')
            }
            const [debitedWallets] = await WalletModel.update(
              { balance: literal(`balance - ${deluxeMembershipCost}`) },
              { where: { id: wallet.id, balance: { [Op.gte]: deluxeMembershipCost } }, transaction }
            )
            if (debitedWallets === 0) {
              throw new UpgradeError('Insuffienct funds in Wallet')
            }
          }
          const [upgradedUsers] = await UserModel.update(
            { role: security.roles.deluxe, deluxeToken: security.deluxeToken(user.email) },
            { where: { id: user.id, role: security.roles.customer }, transaction }
          )
          if (upgradedUsers === 0) {
            throw new UpgradeError('Something went wrong. Please try again!')
          }
          return await UserModel.findByPk(user.id, { transaction })
        })
        if (updatedUser == null) {
          throw new UpgradeError('Something went wrong. Please try again!')
        }
        const userWithStatus = utils.queryResultToJson(updatedUser)
        const updatedToken = security.authorize(userWithStatus)
        security.authenticatedUsers.put(updatedToken, userWithStatus)
        res.status(200).json({ status: 'success', data: { confirmation: 'Congratulations! You are now a deluxe member!', token: updatedToken } })
      } catch (error) {
        res.status(400).json({ status: 'error', error: error instanceof UpgradeError ? error.message : 'Something went wrong. Please try again!' })
      }
    } catch (err: unknown) {
      res.status(400).json({ status: 'error', error: 'Something went wrong: ' + utils.getErrorMessage(err) })
    }
  }
}

export function deluxeMembershipStatus () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (security.isCustomer(req)) {
      res.status(200).json({ status: 'success', data: { membershipCost: deluxeMembershipCost } })
    } else if (security.isDeluxe(req)) {
      res.status(400).json({ status: 'error', error: 'You are already a deluxe member!' })
    } else {
      res.status(400).json({ status: 'error', error: 'You are not eligible for deluxe membership!' })
    }
  }
}
