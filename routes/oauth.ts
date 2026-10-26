/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import crypto from 'node:crypto'
import config from 'config'
import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const googleTokenInfoUrl = 'https://oauth2.googleapis.com/tokeninfo'

async function verifiedGoogleEmail (accessToken: string): Promise<string | null> {
  const clientId = config.has('application.googleOauth.clientId') ? config.get<string>('application.googleOauth.clientId') : ''
  if (!clientId) return null

  const response = await fetch(googleTokenInfoUrl, {
    method: 'POST',
    body: new URLSearchParams({ access_token: accessToken }),
    signal: AbortSignal.timeout(5000)
  })
  if (!response.ok) return null

  const tokenInfo = await response.json()
  if (tokenInfo?.aud !== clientId) return null
  if (String(tokenInfo.email_verified) !== 'true') return null
  if (!(Number(tokenInfo.expires_in) > 0)) return null
  return typeof tokenInfo.email === 'string' && tokenInfo.email !== '' ? tokenInfo.email : null
}

export function oauthLogin () {
  return async (req: Request, res: Response) => {
    const accessToken = req.body?.accessToken
    if (typeof accessToken !== 'string' || !/^[\w.~+/-]{1,4096}=*$/.test(accessToken)) {
      res.status(400).json({ status: 'error', message: 'Missing or malformed access token.' })
      return
    }

    let email: string | null
    try {
      email = await verifiedGoogleEmail(accessToken)
    } catch {
      email = null
    }
    if (!email) {
      res.status(401).json({ status: 'error', message: 'Invalid OAuth access token.' })
      return
    }

    let user: UserModel
    try {
      [user] = await UserModel.findOrCreate({
        where: { email },
        defaults: { email, password: crypto.randomBytes(32).toString('base64') }
      })
    } catch {
      res.status(401).json({ status: 'error', message: 'Invalid OAuth access token.' })
      return
    }

    challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => { return user.email === 'bjoern.kimminich@gmail.com' })

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

    const authenticatedUser: any = utils.queryResultToJson(user)
    const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.id } })
    const token = security.authorize(authenticatedUser)
    authenticatedUser.bid = basket.id
    security.authenticatedUsers.put(token, authenticatedUser)
    res.json({ authentication: { token, bid: basket.id, umail: user.email } })
  }
}
