/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { WalletModel } from '../models/wallet'
import { chargeCard, walletTopUpLimits } from '../lib/payment'

export function getWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
    if (wallet != null) {
      res.status(200).json({ status: 'success', data: wallet.balance })
    } else {
      res.status(404).json({ status: 'error' })
    }
  }
}

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const amount = req.body.balance
    if (typeof amount !== 'number' || !Number.isFinite(amount) || amount < walletTopUpLimits.min || amount > walletTopUpLimits.max) {
      res.status(400).json({ status: 'error', message: `Amount must be between ${walletTopUpLimits.min} and ${walletTopUpLimits.max}.` })
      return
    }
    try {
      await chargeCard(req.body.UserId, req.body.paymentId, amount)
    } catch {
      res.status(402).json({ status: 'error', message: 'Payment not accepted.' })
      return
    }
    try {
      await WalletModel.increment({ balance: amount }, { where: { UserId: req.body.UserId } })
      res.status(200).json({ status: 'success', data: amount })
    } catch {
      res.status(404).json({ status: 'error' })
    }
  }
}
