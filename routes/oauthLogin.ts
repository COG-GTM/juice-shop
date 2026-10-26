/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const googleTokenInfoUrl = 'https://oauth2.googleapis.com/tokeninfo'

interface GoogleTokenInfo {
  aud?: string
  azp?: string
  email?: string
  email_verified?: string | boolean
  expires_in?: string | number
}

async function verifyGoogleAccessToken (accessToken: string): Promise<string | null> {
  const clientId = config.has('application.googleOauth.clientId') ? config.get<string>('application.googleOauth.clientId') : ''
  if (!clientId) return null

  const response = await fetch(`${googleTokenInfoUrl}?access_token=${encodeURIComponent(accessToken)}`, { signal: AbortSignal.timeout(5000) })
  if (!response.ok) return null

  const tokenInfo = await response.json() as GoogleTokenInfo
  const issuedForThisApp = tokenInfo.aud === clientId || tokenInfo.azp === clientId
  const emailVerified = tokenInfo.email_verified === true || tokenInfo.email_verified === 'true'
  const notExpired = Number(tokenInfo.expires_in) > 0
  if (!issuedForThisApp || !emailVerified || !notExpired || typeof tokenInfo.email !== 'string' || tokenInfo.email === '') {
    return null
  }
  return tokenInfo.email
}

export function oauthLogin () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const accessToken = req.body?.accessToken
    if (typeof accessToken !== 'string' || accessToken === '') {
      res.status(401).send(res.__('Invalid email or password.'))
      return
    }

    let email: string | null
    try {
      email = await verifyGoogleAccessToken(accessToken)
    } catch {
      email = null
    }
    if (email === null) {
      res.status(401).send(res.__('Invalid email or password.'))
      return
    }

    try {
      let user = await UserModel.findOne({ where: { email } })
      if (user === null) {
        user = await UserModel.create({ email, password: crypto.randomBytes(32).toString('hex') })
      }

      if (user.totpSecret) {
        res.status(401).json({
          status: 'totp_token_required',
          data: {
            tmpToken: security.authorize({
              userId: user.id,
              type: 'password_valid_needs_second_factor_token'
            })
          }
        })
        return
      }

      challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => { return user?.email === 'bjoern.kimminich@gmail.com' })

      const authenticatedUser: { status: string, data: UserModel, bid?: number } = utils.queryResultToJson(user)
      const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.id } })
      const token = security.authorize(authenticatedUser)
      authenticatedUser.bid = basket.id
      security.authenticatedUsers.put(token, authenticatedUser)
      res.json({ authentication: { token, bid: basket.id, umail: user.email } })
    } catch (error) {
      next(error)
    }
  }
}
