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
import { login } from './helpers/auth'

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
  void it('POST update username is rejected for cross-site Origin', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'http://htmledit.squarefree.com')
      .type('form')
      .send('username=CSRF')
      .redirects(0)

    assert.equal(res.status, 403)
    const profile = await request(app).get('/profile').set(authHeader)
    assert.ok(!profile.text.includes('CSRF'))
  })

  void it('POST update username is rejected for cross-site Referer without Origin', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Referer', 'http://attacker.example/csrf.html')
      .type('form')
      .send('username=CSRF')
      .redirects(0)

    assert.equal(res.status, 403)
  })

  void it('POST update username is rejected for opaque Origin', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'null')
      .type('form')
      .send('username=CSRF')
      .redirects(0)

    assert.equal(res.status, 403)
  })

  void it('POST update username from same origin sets SameSite=Strict token cookie', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Host', 'localhost:3000')
      .set('Origin', 'http://localhost:3000')
      .type('form')
      .send('username=Localhorst')
      .redirects(0)

    assert.equal(res.status, 302)
    const cookies = [res.headers['set-cookie'] ?? []].flat()
    assert.ok(cookies.some((c: string) => c.startsWith('token=') && c.includes('SameSite=Strict')))
  })
})
