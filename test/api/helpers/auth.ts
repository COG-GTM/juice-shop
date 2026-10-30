/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import request from 'supertest'
import sinon from 'sinon'
import config from 'config'
import { generateSync } from 'otplib'
import type { Express } from 'express'
import * as security from '../../../lib/insecurity'

const jsonHeader = { 'content-type': 'application/json' }

export async function login (app: Express, { email, password, totpSecret }: { email: string, password: string, totpSecret?: string }) {
  const loginRes = await request(app)
    .post('/rest/user/login')
    .set(jsonHeader)
    .send({ email, password })

  if (loginRes.status !== 200 && loginRes.body?.status !== 'totp_token_required') {
    throw new Error(`Failed to login '${email}': ${loginRes.status}`)
  }

  if (loginRes.body.status && loginRes.body.status === 'totp_token_required') {
    if (!totpSecret) {
      throw new Error('login with totp required but no totp secret provided to login function')
    }

    const totpRes = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken: loginRes.body.data.tmpToken,
        totpToken: generateSync({ secret: totpSecret })
      })

    return totpRes.body.authentication
  }

  return loginRes.body.authentication
}

export async function register (app: Express, { email, password, totpSecret }: { email: string, password: string, totpSecret?: string }) {
  const res = await request(app)
    .post('/api/Users/')
    .set(jsonHeader)
    .send({
      email,
      password,
      passwordRepeat: password,
      securityQuestion: null,
      securityAnswer: null
    })

  if (res.status !== 201 && res.status !== 200) {
    throw new Error(`Failed to register '${email}': ${res.status}`)
  }

  if (totpSecret) {
    const { token } = await login(app, { email, password })

    const setupRes = await request(app)
      .post('/rest/2fa/setup')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({
        password,
        setupToken: security.authorize({
          secret: totpSecret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret: totpSecret })
      })

    if (setupRes.status !== 200) {
      throw new Error(`Failed to enable 2fa for user: '${email}'`)
    }
  }

  return res
}

export async function loginWithGoogle (app: Express, email: string, tokenInfo: Record<string, unknown> = {}) {
  const fetchStub = sinon.stub(globalThis, 'fetch').resolves(new Response(JSON.stringify({
    aud: config.get<string>('application.googleOauth.clientId'),
    email,
    email_verified: 'true',
    expires_in: '3599',
    ...tokenInfo
  }), { status: 200, headers: { 'content-type': 'application/json' } }))
  try {
    return await request(app)
      .post('/rest/user/oauth-login')
      .set(jsonHeader)
      .send({ accessToken: 'test-access-token' })
  } finally {
    fetchStub.restore()
  }
}

export async function loginAsGoogleUser (app: Express, email: string) {
  const res = await loginWithGoogle(app, email)
  if (res.status !== 200) {
    throw new Error(`Failed to login '${email}' via Google: ${res.status}`)
  }
  return res.body.authentication
}
