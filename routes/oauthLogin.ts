/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import crypto from 'node:crypto'
import config from 'config'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const GOOGLE_TOKENINFO_URL = 'https://oauth2.googleapis.com/tokeninfo'

interface GoogleTokenInfo {
  aud?: string
  email?: string
  email_verified?: string | boolean
  expires_in?: string | number
}

async function verifyGoogleAccessToken (accessToken: string): Promise<string | null> {
  const response = await fetch(`${GOOGLE_TOKENINFO_URL}?access_token=${encodeURIComponent(accessToken)}`, { signal: AbortSignal.timeout(5000) })
  if (!response.ok) return null
  const tokenInfo = await response.json() as GoogleTokenInfo
  if (tokenInfo.aud !== config.get<string>('application.googleOauth.clientId')) return null
  if (Number(tokenInfo.expires_in) <= 0) return null
  if (String(tokenInfo.email_verified) !== 'true' || typeof tokenInfo.email !== 'string' || !tokenInfo.email) return null
  return tokenInfo.email
}

export function oauthLogin () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const accessToken = req.body?.accessToken
    if (typeof accessToken !== 'string' || !accessToken) {
      return res.status(400).send('Missing OAuth access token.')
    }
    let email: string | null
    try {
      email = await verifyGoogleAccessToken(accessToken)
    } catch (error) {
      return next(error)
    }
    if (!email) {
      return res.status(401).send('Invalid OAuth access token.')
    }

    try {
      let user = await UserModel.findOne({ where: { email } })
      if (!user) {
        user = await UserModel.create({ email, password: crypto.randomBytes(32).toString('hex') })
      }
      challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => { return email === 'bjoern.kimminich@gmail.com' })

      const authenticatedUser = utils.queryResultToJson(user.toJSON())
      if (authenticatedUser.data.totpSecret !== '') {
        return res.status(401).json({
          status: 'totp_token_required',
          data: {
            tmpToken: security.authorize({
              userId: authenticatedUser.data.id,
              type: 'password_valid_needs_second_factor_token'
            })
          }
        })
      }
      const [basket] = await BasketModel.findOrCreate({ where: { UserId: authenticatedUser.data.id } })
      const token = security.authorize(authenticatedUser)
      security.authenticatedUsers.put(token, { ...authenticatedUser, bid: basket.id })
      res.json({ authentication: { token, bid: basket.id, umail: authenticatedUser.data.email } })
    } catch (error) {
      next(error)
    }
  }
}
