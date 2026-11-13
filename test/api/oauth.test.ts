/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { UserModel } from '../../models/user'
import { loginWithGoogle, validGoogleTokenInfo, withGoogleTokenInfo } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }
const derivedPassword = (email: string) => Buffer.from(email.split('').reverse().join('')).toString('base64')

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/oauth', () => {
  void it('POST with verified Google token creates account and returns session', async () => {
    const authentication = await loginWithGoogle(app, 'alice.oauth@example.com')

    assert.equal(typeof authentication.token, 'string')
    assert.equal(authentication.umail, 'alice.oauth@example.com')
  })

  void it('POST with verified Google token logs in same account again', async () => {
    const first = await loginWithGoogle(app, 'repeat.oauth@example.com')
    const second = await loginWithGoogle(app, 'repeat.oauth@example.com')

    assert.equal(first.bid, second.bid)
  })

  void it('POST with verified Google token logs in seeded Google account', async () => {
    const authentication = await loginWithGoogle(app, 'bjoern.kimminich@gmail.com')

    assert.equal(authentication.umail, 'bjoern.kimminich@gmail.com')
  })

  void it('POST without access token is rejected', async () => {
    const res = await request(app).post('/rest/user/oauth').set(jsonHeader).send({})

    assert.equal(res.status, 400)
  })

  void it('POST with token Google rejects is rejected', async () => {
    const res = await withGoogleTokenInfo(null, async () => await request(app)
      .post('/rest/user/oauth').set(jsonHeader).send({ accessToken: 'ya29.invalid' }))

    assert.equal(res.status, 401)
  })

  void it('POST with token issued to another client is rejected', async () => {
    const res = await withGoogleTokenInfo({ ...validGoogleTokenInfo('mallory@example.com'), aud: 'other-client.apps.googleusercontent.com' }, async () => await request(app)
      .post('/rest/user/oauth').set(jsonHeader).send({ accessToken: 'ya29.foreign' }))

    assert.equal(res.status, 401)
  })

  void it('POST with token for unverified email is rejected', async () => {
    const res = await withGoogleTokenInfo({ ...validGoogleTokenInfo('unverified@example.com'), email_verified: 'false' }, async () => await request(app)
      .post('/rest/user/oauth').set(jsonHeader).send({ accessToken: 'ya29.unverified' }))

    assert.equal(res.status, 401)
  })

  void it('POST with expired token is rejected', async () => {
    const res = await withGoogleTokenInfo({ ...validGoogleTokenInfo('expired@example.com'), expires_in: '0' }, async () => await request(app)
      .post('/rest/user/oauth').set(jsonHeader).send({ accessToken: 'ya29.expired' }))

    assert.equal(res.status, 401)
  })

  void it('POST does not hand over a password account pre-registered by someone else', async () => {
    await request(app).post('/api/Users').set(jsonHeader)
      .send({ email: 'victim.oauth@example.com', password: 'oauth:attackerKnows', passwordRepeat: 'oauth:attackerKnows' })
      .expect(201)

    const res = await withGoogleTokenInfo(validGoogleTokenInfo('victim.oauth@example.com'), async () => await request(app)
      .post('/rest/user/oauth').set(jsonHeader).send({ accessToken: 'ya29.victim' }))

    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })
})

void describe('/rest/user/login for Google sign-in accounts', () => {
  void it('POST with base64-encoded reversed email of Google-created account is rejected', async () => {
    await loginWithGoogle(app, 'carol.oauth@example.com')

    const res = await request(app).post('/rest/user/login').set(jsonHeader)
      .send({ email: 'carol.oauth@example.com', password: derivedPassword('carol.oauth@example.com') })

    assert.equal(res.status, 401)
  })

  void it('POST with base64-encoded reversed email of seeded Google account is rejected', async () => {
    const res = await request(app).post('/rest/user/login').set(jsonHeader)
      .send({ email: 'bjoern.kimminich@gmail.com', password: derivedPassword('bjoern.kimminich@gmail.com') })

    assert.equal(res.status, 401)
  })

  void it('POST with stored placeholder value of Google-created account is rejected', async () => {
    await loginWithGoogle(app, 'dave.oauth@example.com')
    const user = await UserModel.findOne({ where: { email: 'dave.oauth@example.com' } })

    const res = await request(app).post('/rest/user/login').set(jsonHeader)
      .send({ email: 'dave.oauth@example.com', password: user?.password })

    assert.equal(res.status, 401)
  })
})
