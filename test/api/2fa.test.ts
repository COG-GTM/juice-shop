/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import request from 'supertest'
import config from 'config'
import jwt from 'jsonwebtoken'
import { generateSync } from 'otplib'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }

let app: Express

function getStatus (token: string) {
  return request(app)
    .get('/rest/2fa/status')
    .set({
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    })
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/2fa/verify', () => {
  void it('POST should return a valid authentication when a valid tmp token is passed', async () => {
    const tmpTokenWurstbrot = security.authorize({
      userId: 10,
      type: 'password_valid_needs_second_factor_token'
    })

    const totpToken = generateSync({ secret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })

    const res = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken: tmpTokenWurstbrot,
        totpToken
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(typeof res.body.authentication.umail, 'string')
    assert.equal(typeof res.body.authentication.bid, 'number')
    assert.equal(res.body.authentication.umail, `wurstbrot@${config.get<string>('application.domain')}`)
  })

  void it('POST should fail if a invalid totp token is used', async () => {
    const tmpTokenWurstbrot = security.authorize({
      userId: 10,
      type: 'password_valid_needs_second_factor_token'
    })

    const totpToken = generateSync({ secret: 'BI6KJAURX3LL5VQI2ZBFVLUWSBYBDX4H' })

    const res = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken: tmpTokenWurstbrot,
        totpToken
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail if a unsigned tmp token is used', async () => {
    const tmpTokenWurstbrot = jwt.sign({
      userId: 10,
      type: 'password_valid_needs_second_factor_token'
    }, 'this_surly_isnt_the_right_key')

    const totpToken = generateSync({ secret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })

    const res = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken: tmpTokenWurstbrot,
        totpToken
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail if an alg none tmp token is used', async () => {
    const tmpToken = forgeToken('none', {
      userId: 1,
      type: 'password_valid_needs_second_factor_token'
    })

    const res = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken,
        totpToken: '000000'
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail if an HS256 tmp token signed with the public key is used', async () => {
    const tmpToken = forgeToken('HS256', {
      userId: 10,
      type: 'password_valid_needs_second_factor_token'
    }, security.publicKey)

    const res = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken,
        totpToken: generateSync({ secret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail for a user without 2fa even with a valid tmp token', async () => {
    const user = await UserModel.findOne({ where: { email: `jim@${config.get<string>('application.domain')}` } })
    assert.ok(user)
    assert.equal(user.totpSecret, '')

    const tmpToken = security.authorize({
      userId: user.id,
      type: 'password_valid_needs_second_factor_token'
    })

    const res = await request(app)
      .post('/rest/2fa/verify')
      .set(jsonHeader)
      .send({
        tmpToken,
        totpToken: '000000'
      })

    assert.equal(res.status, 401)
  })
})

void describe('/rest/2fa/status', () => {
  void it('GET should indicate 2fa is setup for 2fa enabled users', async () => {
    const { token } = await login(app, {
      email: `wurstbrot@${config.get<string>('application.domain')}`,
      password: 'EinBelegtesBrotMitSchinkenSCHINKEN!',
      totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'
    })

    const res = await getStatus(token)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.setup, 'boolean')
    assert.equal(res.body.setup, true)
  })

  void it('GET should indicate 2fa is not setup for users with 2fa disabled', async () => {
    const { token } = await login(app, {
      email: `J12934@${config.get<string>('application.domain')}`,
      password: '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'
    })

    const res = await getStatus(token)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.setup, 'boolean')
    assert.equal(typeof res.body.secret, 'string')
    assert.equal(typeof res.body.email, 'string')
    assert.equal(typeof res.body.setupToken, 'string')
    assert.equal(res.body.setup, false)
    assert.equal(res.body.email, `J12934@${config.get<string>('application.domain')}`)
  })

  void it('GET should return 401 when not logged in', async () => {
    const res = await request(app).get('/rest/2fa/status')

    assert.equal(res.status, 401)
  })
})

void describe('JWT authentication cannot bypass 2fa setup or disable', () => {
  async function assertForgedIdentityCannotChangeTwoFactor (endpoint: 'setup' | 'disable') {
    const user = await UserModel.findByPk(10)
    assert.ok(user)
    assert.equal(user.email, `wurstbrot@${config.get<string>('application.domain')}`)
    const originalTotpSecret = user.totpSecret
    assert.ok(originalTotpSecret)

    const token = forgeToken('none', {
      data: {
        id: user.id,
        email: user.email,
        password: security.hash('letmein'),
        totpSecret: 'x'
      }
    })

    const whoamiRes = await request(app)
      .get('/rest/user/whoami')
      .set({
        Authorization: `Bearer ${token}`,
        Cookie: `token=${token}`
      })

    assert.equal(whoamiRes.status, 200)
    assert.equal(whoamiRes.body.user.id, undefined)
    assert.equal(whoamiRes.body.user.email, undefined)

    const res = await request(app)
      .post(`/rest/2fa/${endpoint}`)
      .set({
        Authorization: `Bearer ${token}`,
        'content-type': 'application/json'
      })
      .send({
        password: 'letmein',
        setupToken: security.authorize({ secret: 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7', type: 'totp_setup_secret' }),
        initialToken: generateSync({ secret: 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7' })
      })

    assert.equal(res.status, 401)
    const unchangedUser = await UserModel.findByPk(user.id)
    assert.equal(unchangedUser?.totpSecret, originalTotpSecret)
  }

  void it('POST disable should reject an alg none identity after whoami', async () => {
    await assertForgedIdentityCannotChangeTwoFactor('disable')
  })

  void it('POST setup should reject an alg none identity after whoami', async () => {
    await assertForgedIdentityCannotChangeTwoFactor('setup')
  })
})

function encodeBase64Url (value: object) {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

function forgeToken (algorithm: string, payload: object, hmacKey?: string) {
  const header = encodeBase64Url({ alg: algorithm, typ: 'JWT' })
  const encodedPayload = encodeBase64Url(payload)
  const signingInput = `${header}.${encodedPayload}`
  const signature = algorithm === 'HS256'
    ? crypto.createHmac('sha256', hmacKey ?? '').update(signingInput).digest('base64url')
    : ''
  return `${signingInput}.${signature}`
}

void describe('/rest/2fa/setup', () => {
  void it('POST should be able to setup 2fa for accounts without 2fa enabled', async () => {
    const email = 'fooooo1@bar.com'
    const password = '123456'
    const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password })
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
          secret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret })
      })

    assert.equal(setupRes.status, 200)

    const statusRes = await getStatus(token)

    assert.equal(statusRes.status, 200)
    assert.equal(typeof statusRes.body.setup, 'boolean')
    assert.equal(statusRes.body.setup, true)
  })

  void it('POST should fail if the password doesnt match', async () => {
    const email = 'fooooo2@bar.com'
    const password = '123456'
    const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password })
    const { token } = await login(app, { email, password })

    const res = await request(app)
      .post('/rest/2fa/setup')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({
        password: password + ' this makes the password wrong',
        setupToken: security.authorize({
          secret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret })
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail if the initial token is incorrect', async () => {
    const email = 'fooooo3@bar.com'
    const password = '123456'
    const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password })
    const { token } = await login(app, { email, password })

    const res = await request(app)
      .post('/rest/2fa/setup')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({
        password,
        setupToken: security.authorize({
          secret,
          type: 'totp_setup_secret'
        }),
        initialToken: generateSync({ secret: 'OJQOJNTB46VLWUO4TVKXIULU2WLPFQOJ' })
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail if the token is of the wrong type', async () => {
    const email = 'fooooo4@bar.com'
    const password = '123456'
    const secret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password })
    const { token } = await login(app, { email, password })

    const res = await request(app)
      .post('/rest/2fa/setup')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({
        password,
        setupToken: security.authorize({
          secret,
          type: 'totp_setup_secret_foobar'
        }),
        initialToken: generateSync({ secret })
      })

    assert.equal(res.status, 401)
  })

  void it('POST should fail if the account has already set up 2fa', async () => {
    const email = `wurstbrot@${config.get<string>('application.domain')}`
    const password = 'EinBelegtesBrotMitSchinkenSCHINKEN!'
    const totpSecret = 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'

    const { token } = await login(app, { email, password, totpSecret })

    const res = await request(app)
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

    assert.equal(res.status, 401)
  })
})

void describe('/rest/2fa/disable', () => {
  void it('POST should be able to disable 2fa for account with 2fa enabled', async () => {
    const email = 'fooooodisable1@bar.com'
    const password = '123456'
    const totpSecret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password, totpSecret })
    const { token } = await login(app, { email, password, totpSecret })

    const statusRes1 = await getStatus(token)
    assert.equal(statusRes1.status, 200)
    assert.equal(statusRes1.body.setup, true)

    const disableRes = await request(app)
      .post('/rest/2fa/disable')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({ password })

    assert.equal(disableRes.status, 200)

    const statusRes2 = await getStatus(token)
    assert.equal(statusRes2.status, 200)
    assert.equal(statusRes2.body.setup, false)
  })

  void it('POST should not be possible to disable 2fa without the correct password', async () => {
    const email = 'fooooodisable2@bar.com'
    const password = '123456'
    const totpSecret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'

    await register(app, { email, password, totpSecret })
    const { token } = await login(app, { email, password, totpSecret })

    const statusRes1 = await getStatus(token)
    assert.equal(statusRes1.status, 200)
    assert.equal(statusRes1.body.setup, true)

    const disableRes = await request(app)
      .post('/rest/2fa/disable')
      .set({
        Authorization: 'Bearer ' + token,
        'content-type': 'application/json'
      })
      .send({ password: password + ' this makes the password wrong' })

    assert.equal(disableRes.status, 401)

    const statusRes2 = await getStatus(token)
    assert.equal(statusRes2.status, 200)
    assert.equal(statusRes2.body.setup, true)
  })
})
