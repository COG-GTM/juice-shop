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
import { login, register } from './helpers/auth'

let app: Express
let authHeader: { Cookie: string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  authHeader = { Cookie: `token=${token}` }
}, { timeout: 60000 })

void describe('/profile', () => {
  void it('GET user profile is forbidden for unauthenticated user', async () => {
    const res = await request(app)
      .get('/profile')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes(`<h1>${config.get<string>('application.name')} (Express`))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET user profile of authenticated user', async () => {
    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('id="email" type="email" name="email" value="jim@juice-sh.op"'))
  })

  void it('POST update username of authenticated user', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', 'Localhorst')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('GET user profile is rejected for a logged out cookie token', async () => {
    await register(app, { email: 'profile-logout@be.rt', password: 'kunigunde' })
    const { token } = await login(app, { email: 'profile-logout@be.rt', password: 'kunigunde' })

    await request(app).get('/profile').set('Cookie', `token=${token}`).expect(200)
    await request(app).post('/rest/user/logout').set({ Authorization: `Bearer ${token}`, Cookie: `token=${token}` }).expect(204)

    const res = await request(app).get('/profile').set('Cookie', `token=${token}`)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET user profile is rejected for a cookie token of a session ended by password change', async () => {
    await register(app, { email: 'profile-password@be.rt', password: 'kunigunde' })
    const { token: oldToken } = await login(app, { email: 'profile-password@be.rt', password: 'kunigunde' })
    const { token } = await login(app, { email: 'profile-password@be.rt', password: 'kunigunde' })

    await request(app).get('/profile').set('Cookie', `token=${oldToken}`).expect(200)
    await request(app)
      .get('/rest/user/change-password?current=kunigunde&new=foobar&repeat=foobar')
      .set({ Authorization: `Bearer ${token}` })
      .expect(200)

    const res = await request(app).get('/profile').set('Cookie', `token=${oldToken}`)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
    await request(app).get('/profile').set('Cookie', `token=${token}`).expect(200)
  })
})
