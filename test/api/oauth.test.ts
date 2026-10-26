/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { challenges } from '../../data/datacache'
import { UserModel } from '../../models/user'
import { googleTokenInfoUrl } from '../../routes/oauth'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }
const clientId = config.get<string>('application.googleOauth.clientId')
const originalFetch = globalThis.fetch

function stubGoogleTokenInfo (tokenInfo: Record<string, unknown>, status = 200) {
  const calls: Array<{ url: string, init?: RequestInit }> = []
  mock.method(globalThis, 'fetch', async (url: string | URL | Request, init?: RequestInit) => {
    if (String(url) !== googleTokenInfoUrl) return await originalFetch(url, init)
    calls.push({ url: String(url), init })
    return new Response(JSON.stringify(tokenInfo), { status, headers: { 'content-type': 'application/json' } })
  })
  return calls
}

function derivedPassword (email: string) {
  return Buffer.from(email.split('').reverse().join('')).toString('base64')
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

afterEach(() => {
  mock.restoreAll()
})

void describe('/rest/user/oauth', () => {
  void it('POST with a verified Google access token issues a session and creates the account', async () => {
    const calls = stubGoogleTokenInfo({ aud: clientId, azp: clientId, email: 'oauth.newbie@gmail.com', email_verified: 'true', expires_in: '3599' })

    const res = await request(app)
      .post('/rest/user/oauth')
      .set(jsonHeader)
      .send({ accessToken: 'ya29.valid-token' })

    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(res.body.authentication.umail, 'oauth.newbie@gmail.com')
    assert.equal(calls.length, 1)
    assert.equal(calls[0].init?.method, 'POST')
    assert.equal(String(calls[0].init?.body), 'access_token=ya29.valid-token')

    const whoami = await request(app)
      .get('/rest/user/whoami')
      .set({ Authorization: 'Bearer ' + res.body.authentication.token, Cookie: 'token=' + res.body.authentication.token })
    assert.equal(whoami.body.user.email, 'oauth.newbie@gmail.com')
  })

  void it('POST login with btoa(reverse(email)) fails for an account created through OAuth', async () => {
    stubGoogleTokenInfo({ aud: clientId, email: 'oauth.victim@gmail.com', email_verified: true, expires_in: 3599 })
    await request(app).post('/rest/user/oauth').set(jsonHeader).send({ accessToken: 'ya29.victim-token' }).expect(200)

    const res = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: 'oauth.victim@gmail.com', password: derivedPassword('oauth.victim@gmail.com') })

    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })

  void it('POST login with btoa(reverse(email)) fails for Bjoern\'s seeded Google account', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: 'bjoern.kimminich@gmail.com', password: derivedPassword('bjoern.kimminich@gmail.com') })

    assert.equal(res.status, 401)
  })

  void it('POST rejects a token issued to another OAuth client', async () => {
    stubGoogleTokenInfo({ aud: 'someone-else.apps.googleusercontent.com', email: 'oauth.confused@gmail.com', email_verified: 'true', expires_in: '3599' })

    const res = await request(app).post('/rest/user/oauth').set(jsonHeader).send({ accessToken: 'ya29.foreign-token' })

    assert.equal(res.status, 401)
    assert.equal(await UserModel.count({ where: { email: 'oauth.confused@gmail.com' } }), 0)
  })

  void it('POST rejects a token whose email is not verified', async () => {
    stubGoogleTokenInfo({ aud: clientId, email: 'oauth.unverified@gmail.com', email_verified: 'false', expires_in: '3599' })

    const res = await request(app).post('/rest/user/oauth').set(jsonHeader).send({ accessToken: 'ya29.unverified-token' })

    assert.equal(res.status, 401)
  })

  void it('POST rejects a token Google does not accept', async () => {
    stubGoogleTokenInfo({ error: 'invalid_token' }, 400)

    const res = await request(app).post('/rest/user/oauth').set(jsonHeader).send({ accessToken: 'ya29.forged-token' })

    assert.equal(res.status, 401)
  })

  void it('POST without an access token is rejected without calling Google', async () => {
    const calls = stubGoogleTokenInfo({ aud: clientId, email: 'x@gmail.com', email_verified: 'true', expires_in: '3599' })

    const res = await request(app).post('/rest/user/oauth').set(jsonHeader).send({ email: 'bjoern.kimminich@gmail.com' })

    assert.equal(res.status, 400)
    assert.equal(calls.length, 0)
  })

  void it('POST with Bjoern\'s verified Google token solves "Login Bjoern"', async () => {
    stubGoogleTokenInfo({ aud: clientId, email: 'bjoern.kimminich@gmail.com', email_verified: 'true', expires_in: '3599' })

    const res = await request(app).post('/rest/user/oauth').set(jsonHeader).send({ accessToken: 'ya29.bjoern-token' })

    assert.equal(res.status, 200)
    assert.equal(challenges.oauthUserPasswordChallenge.solved, true)
  })
})
