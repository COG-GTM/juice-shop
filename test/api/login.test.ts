/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { oauthLogin } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/login', () => {
  void it('POST login newly created user', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'kalli@kasper.le',
        password: 'kallliiii'
      })
      .expect(201)

    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'kalli@kasper.le',
        password: 'kallliiii'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(typeof res.body.authentication.umail, 'string')
    assert.equal(typeof res.body.authentication.bid, 'number')
  })

  void it('POST login non-existing user', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'otto@mei.er',
        password: 'ooootto'
      })

    assert.equal(res.status, 401)
  })

  void it('POST login without credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: undefined,
        password: undefined
      })

    assert.equal(res.status, 401)
  })

  void it('POST login with admin credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'admin@' + config.get<string>('application.domain'),
        password: 'admin123'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with support-team credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'support@' + config.get<string>('application.domain'),
        password: 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with MC SafeSearch credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'mc.safesearch@' + config.get<string>('application.domain'),
        password: 'Mr. N00dles'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with Amy credentials', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'amy@' + config.get<string>('application.domain'),
        password: 'K1f.....................'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with wurstbrot credentials expects 2FA token', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'wurstbrot@' + config.get<string>('application.domain'),
        password: 'EinBelegtesBrotMitSchinkenSCHINKEN!'
      })

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.tmpToken, 'string')
    assert.equal(res.body.status, 'totp_token_required')
  })

  void it('POST login as bjoern.kimminich@gmail.com with password derived from email fails', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern.kimminich@gmail.com',
        password: Buffer.from('bjoern.kimminich@gmail.com'.split('').reverse().join('')).toString('base64')
      })

    assert.equal(res.status, 401)
  })

  void it('POST login with WHERE-clause disabling SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: '\' or 1=1--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with known email "admin@juice-sh.op" in SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'admin@' + config.get<string>('application.domain') + '\'--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with known email "jim@juice-sh.op" in SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'jim@' + config.get<string>('application.domain') + '\'--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with known email "bender@juice-sh.op" in SQL injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bender@' + config.get<string>('application.domain') + '\'--',
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with non-existing email "acc0unt4nt@juice-sh.op" via UNION SELECT injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: `' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', 'acc0unt4nt@${config.get<string>('application.domain')}' as 'email', '12345' as 'password', 'accounting' as 'role', '' as deluxeToken, '1.2.3.4' as 'lastLoginIp' , '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '1999-08-16 14:14:41.644 +00:00' as 'createdAt', '1999-08-16 14:33:41.930 +00:00' as 'updatedAt', null as 'deletedAt')--`,
        password: undefined
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('POST login with query-breaking SQL Injection attack', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: '\';',
        password: undefined
      })

    assert.equal(res.status, 401)
  })
})

void describe('/rest/saveLoginIp', () => {
  void it('GET last login IP will be saved as True-Client-IP header value', async () => {
    const { token } = await oauthLogin(app, 'bjoern.kimminich@gmail.com')

    const res = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + token,
        'true-client-ip': '1.2.3.4'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.lastLoginIp, '1.2.3.4')
  })

  void it('GET last login IP will be saved as remote IP when True-Client-IP is not present', { skip: 'FIXME Started to fail regularly on CI under Linux' }, async () => {
    const { token } = await oauthLogin(app, 'bjoern.kimminich@gmail.com')

    const res = await request(app)
      .get('/rest/saveLoginIp')
      .set({
        Authorization: 'Bearer ' + token
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.lastLoginIp, '127.0.0.1')
  })
})

void describe('/rest/user/oauth-login', () => {
  const clientId = config.get<string>('application.googleOauth.clientId')

  async function oauthLoginWithTokenInfo (tokenInfo: Record<string, unknown>, status = 200) {
    const originalFetch = globalThis.fetch
    const requestedUrls: string[] = []
    globalThis.fetch = async (url: string | URL | Request) => {
      requestedUrls.push(url.toString())
      return new Response(JSON.stringify(tokenInfo), { status, headers: { 'content-type': 'application/json' } })
    }
    try {
      const res = await request(app)
        .post('/rest/user/oauth-login')
        .set({ 'content-type': 'application/json' })
        .send({ accessToken: 'some&access=token' })
      return { res, requestedUrls }
    } finally {
      globalThis.fetch = originalFetch
    }
  }

  void it('POST OAuth login without access token fails', async () => {
    const res = await request(app)
      .post('/rest/user/oauth-login')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'bjoern.kimminich@gmail.com' })

    assert.equal(res.status, 401)
  })

  void it('POST OAuth login verifies access token with Google', async () => {
    const { res, requestedUrls } = await oauthLoginWithTokenInfo({ aud: clientId, email: 'bjoern.kimminich@gmail.com', email_verified: 'true' })

    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(res.body.authentication.umail, 'bjoern.kimminich@gmail.com')
    assert.deepEqual(requestedUrls, ['https://oauth2.googleapis.com/tokeninfo?access_token=some%26access%3Dtoken'])
  })

  void it('POST OAuth login with access token rejected by Google fails', async () => {
    const { res } = await oauthLoginWithTokenInfo({ error: 'invalid_token' }, 400)

    assert.equal(res.status, 401)
  })

  void it('POST OAuth login with access token issued to another client fails', async () => {
    const { res } = await oauthLoginWithTokenInfo({ aud: 'attacker-client-id', email: 'bjoern.kimminich@gmail.com', email_verified: 'true' })

    assert.equal(res.status, 401)
  })

  void it('POST OAuth login with unverified email fails', async () => {
    const { res } = await oauthLoginWithTokenInfo({ aud: clientId, email: 'bjoern.kimminich@gmail.com', email_verified: 'false' })

    assert.equal(res.status, 401)
  })

  void it('POST OAuth login creates new account without password derived from email', async () => {
    const email = 'new.oauth.user@gmail.com'
    const { res } = await oauthLoginWithTokenInfo({ aud: clientId, email, email_verified: true })

    assert.equal(res.status, 200)
    assert.equal(res.body.authentication.umail, email)

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email,
        password: Buffer.from(email.split('').reverse().join('')).toString('base64')
      })

    assert.equal(loginRes.status, 401)
  })
})
