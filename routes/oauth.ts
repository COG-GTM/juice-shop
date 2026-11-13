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
import * as models from '../models/index'
import { OAuthIdentityModel } from '../models/oauthIdentity'
import { UserModel } from '../models/user'
import { WalletModel } from '../models/wallet'
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

    let verifiedEmail: string | null
    try {
      verifiedEmail = await verifiedGoogleEmail(accessToken)
    } catch {
      verifiedEmail = null
    }
    if (!verifiedEmail) {
      res.status(401).json({ status: 'error', message: 'Invalid OAuth access token.' })
      return
    }
    const email = verifiedEmail

    let user: UserModel
    try {
      let linked: boolean
      [user, linked] = await models.sequelize.transaction(async (transaction) => {
        const [user, created] = await UserModel.findOrCreate({
          where: { email },
          defaults: { email, password: crypto.randomBytes(32).toString('base64') },
          transaction
        })
        if (created) await OAuthIdentityModel.create({ UserId: user.id }, { transaction })
        return [user, created || await OAuthIdentityModel.count({ where: { UserId: user.id }, transaction }) > 0] as const
      })
      if (!linked) {
        res.status(409).json({ status: 'error', message: 'An account with this email address already exists. Please log in with your password.' })
        return
      }
      await WalletModel.findOrCreate({ where: { UserId: user.id } })
    } catch {
      res.status(401).json({ status: 'error', message: 'Invalid OAuth access token.' })
      return
    }

    if (user.totpSecret) {
      res.status(401).json({
        status: 'totp_token_required',
        data: {
          tmpToken: security.authorize({
            userId: user.id,
            type: 'password_valid_needs_second_factor_token',
            oauth: true
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
    challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => { return user.email === 'bjoern.kimminich@gmail.com' })
    res.json({ authentication: { token, bid: basket.id, umail: user.email } })
  }
}
