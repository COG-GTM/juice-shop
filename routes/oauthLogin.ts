/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import config from 'config'
import { type Request, type Response } from 'express'
import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const googleTokenInfoUrl = 'https://oauth2.googleapis.com/tokeninfo'

interface GoogleTokenInfo {
  aud?: string
  email?: string
  email_verified?: string | boolean
}

export async function verifyGoogleAccessToken (accessToken: string): Promise<string | null> {
  const response = await fetch(`${googleTokenInfoUrl}?access_token=${encodeURIComponent(accessToken)}`, { signal: AbortSignal.timeout(5000) })
  if (!response.ok) {
    return null
  }
  const tokenInfo = await response.json() as GoogleTokenInfo
  const emailVerified = tokenInfo.email_verified === true || tokenInfo.email_verified === 'true'
  if (tokenInfo.aud !== config.get<string>('application.googleOauth.clientId') || !emailVerified || typeof tokenInfo.email !== 'string' || tokenInfo.email === '') {
    return null
  }
  return tokenInfo.email
}

export function oauthLogin () {
  return async (req: Request, res: Response) => {
    const accessToken = req.body?.accessToken
    if (typeof accessToken !== 'string' || accessToken === '') {
      return res.status(401).send(res.__('Invalid email or password.'))
    }

    let email: string | null
    try {
      email = await verifyGoogleAccessToken(accessToken)
    } catch {
      email = null
    }
    if (email === null) {
      return res.status(401).send(res.__('Invalid email or password.'))
    }

    let user = await UserModel.findOne({ where: { email } })
    if (user == null) {
      user = await UserModel.create({ email, password: crypto.randomBytes(32).toString('hex') })
    }

    if (user.totpSecret !== '') {
      return res.status(401).json({
        status: 'totp_token_required',
        data: {
          tmpToken: security.authorize({
            userId: user.id,
            type: 'password_valid_needs_second_factor_token'
          })
        }
      })
    }

    const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.id } })
    const plainUser = utils.queryResultToJson(user)
    const token = security.authorize(plainUser)
    // @ts-expect-error FIXME set new property for original basket
    plainUser.bid = basket.id
    security.authenticatedUsers.put(token, plainUser)
    res.json({ authentication: { token, bid: basket.id, umail: user.email } })
  }
}
