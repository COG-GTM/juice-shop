/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { sessionLifetimeInSeconds } from '../../lib/insecurity'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function freshSession (email: string, password = 'kunigunde') {
  await register(app, { email, password })
  const { token } = await login(app, { email, password })
  return token as string
}

void describe('server-side session lifecycle', () => {
  void it('old token is rejected on wallet, data export and profile update after logout', async () => {
    const token = await freshSession('session.logout@juice-sh.op')
    const bearer = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }

    await request(app).get('/rest/wallet/balance').set(bearer).expect(200)
    await request(app).post('/rest/user/logout').set(bearer).set('Cookie', `token=${token}`).expect(204)

    assert.equal((await request(app).get('/rest/wallet/balance').set(bearer)).status, 401)
    assert.equal((await request(app).post('/rest/user/data-export').set(bearer).send({ format: '1' })).status, 401)
    const profile = await request(app).post('/profile').set('Cookie', `token=${token}`).field('username', 'mallory').redirects(0)
    assert.notEqual(profile.status, 302)
  })

  void it('old token is rejected on wallet and change-password after the password was changed elsewhere', async () => {
    const email = 'session.chpw@juice-sh.op'
    const stolen = await freshSession(email)
    const current = (await login(app, { email, password: 'kunigunde' })).token as string

    await request(app)
      .get('/rest/user/change-password?current=kunigunde&new=foo12345&repeat=foo12345')
      .set('Authorization', `Bearer ${current}`)
      .expect(200)

    assert.equal((await request(app).get('/rest/wallet/balance').set('Authorization', `Bearer ${stolen}`)).status, 401)
    const hijack = await request(app)
      .get('/rest/user/change-password?new=mallory1&repeat=mallory1')
      .set('Authorization', `Bearer ${stolen}`)
    assert.notEqual(hijack.status, 200)
    await login(app, { email, password: 'foo12345' })
  })

  void it('token older than the session lifetime is rejected on wallet', async () => {
    const token = await freshSession('session.expired@juice-sh.op')
    const header = { Authorization: `Bearer ${token}` }
    await request(app).get('/rest/wallet/balance').set(header).expect(200)

    const now = Date.now()
    const clock = mock.method(Date, 'now', () => now + (sessionLifetimeInSeconds + 1) * 1000)
    try {
      assert.equal((await request(app).get('/rest/wallet/balance').set(header)).status, 401)
    } finally {
      clock.mock.restore()
    }
    assert.equal((await request(app).get('/rest/wallet/balance').set(header)).status, 401)
  })
})
