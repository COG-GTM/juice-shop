/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response } from 'express'
import config from 'config'
import crypto from 'node:crypto'

import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import { WalletModel } from '../models/wallet'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const googleTokenInfoUrl = 'https://oauth2.googleapis.com/tokeninfo'

interface GoogleTokenInfo {
  aud?: string
  email?: string
  email_verified?: string | boolean
  expires_in?: string | number
}

async function verifyGoogleAccessToken (accessToken: string): Promise<string | null> {
  const response = await fetch(`${googleTokenInfoUrl}?access_token=${encodeURIComponent(accessToken)}`, { signal: AbortSignal.timeout(5000) })
  if (!response.ok) {
    return null
  }
  const tokenInfo = await response.json() as GoogleTokenInfo
  const isIssuedForThisApp = tokenInfo.aud === config.get<string>('application.googleOauth.clientId')
  const isEmailVerified = String(tokenInfo.email_verified) === 'true'
  const isUnexpired = Number(tokenInfo.expires_in) > 0
  if (!isIssuedForThisApp || !isEmailVerified || !isUnexpired || typeof tokenInfo.email !== 'string' || tokenInfo.email === '') {
    return null
  }
  return tokenInfo.email
}

export function oauthLogin () {
  return async (req: Request, res: Response) => {
    const accessToken = req.body?.accessToken
    if (typeof accessToken !== 'string' || accessToken === '') {
      res.status(400).send('Missing Google access token.')
      return
    }

    let email: string | null
    try {
      email = await verifyGoogleAccessToken(accessToken)
    } catch {
      email = null
    }
    if (!email) {
      res.status(401).send('Invalid Google access token.')
      return
    }

    const [userModel, created] = await UserModel.findOrCreate({
      where: { email },
      defaults: { email, password: crypto.randomBytes(32).toString('hex') }
    })
    if (created) {
      await WalletModel.create({ UserId: userModel.id })
    }
    const user = utils.queryResultToJson(userModel)

    if (user.data.totpSecret) {
      res.status(401).json({
        status: 'totp_token_required',
        data: {
          tmpToken: security.authorize({
            userId: user.data.id,
            type: 'password_valid_needs_second_factor_token'
          })
        }
      })
      return
    }

    const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.data.id } })
    const token = security.authorize(user)
    security.authenticatedUsers.put(token, Object.assign(user, { bid: basket.id }))
    res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
  }
}
