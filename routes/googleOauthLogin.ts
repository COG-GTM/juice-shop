/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'

import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const GOOGLE_TOKENINFO_URL = 'https://oauth2.googleapis.com/tokeninfo'

interface GoogleTokenInfo {
  aud?: string
  azp?: string
  email?: string
  email_verified?: string | boolean
  expires_in?: string | number
}

export async function verifyGoogleAccessToken (accessToken: string): Promise<string | null> {
  const response = await fetch(`${GOOGLE_TOKENINFO_URL}?access_token=${encodeURIComponent(accessToken)}`)
  if (!response.ok) return null
  const tokenInfo = await response.json() as GoogleTokenInfo
  const clientId = config.get<string>('application.googleOauth.clientId')
  const audienceMatches = tokenInfo.aud === clientId || tokenInfo.azp === clientId
  const notExpired = Number(tokenInfo.expires_in) > 0
  const emailVerified = tokenInfo.email_verified === true || tokenInfo.email_verified === 'true'
  if (!audienceMatches || !notExpired || !emailVerified || typeof tokenInfo.email !== 'string' || tokenInfo.email === '') {
    return null
  }
  return tokenInfo.email
}

export function googleOauthLogin () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const accessToken = req.body?.accessToken
    if (typeof accessToken !== 'string' || accessToken === '') {
      return res.status(400).send(res.__('Invalid OAuth access token.'))
    }

    let email: string | null
    try {
      email = await verifyGoogleAccessToken(accessToken)
    } catch {
      email = null
    }
    if (email === null) {
      return res.status(401).send(res.__('Invalid OAuth access token.'))
    }

    try {
      const [userModel] = await UserModel.findOrCreate({
        where: { email },
        defaults: { email, password: crypto.randomBytes(32).toString('hex') }
      })
      const user = utils.queryResultToJson(userModel)
      if (user.data.totpSecret !== '') {
        return res.status(401).json({
          status: 'totp_token_required',
          data: {
            tmpToken: security.authorize({
              userId: user.data.id,
              type: 'password_valid_needs_second_factor_token'
            })
          }
        })
      }
      const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      const token = security.authorize(user)
      security.authenticatedUsers.put(token, { ...user, bid: basket.id })
      res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
    } catch (error) {
      next(error)
    }
  }
}
