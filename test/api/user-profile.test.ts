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

  void it('GET user profile embeds a CSRF token in the username form', async () => {
    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.match(res.text, /<input type="hidden" name="csrfToken" value="[0-9a-f]{64}"/)
  })

  void it('POST update username of authenticated user with valid CSRF token', async () => {
    const profile = await request(app)
      .get('/profile')
      .set(authHeader)
    const csrfToken = /name="csrfToken" value="([0-9a-f]{64})"/.exec(profile.text)?.[1]
    assert.ok(csrfToken)

    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: 'Localhorst', csrfToken })
      .redirects(0)

    assert.equal(res.status, 302)
    assert.ok(res.headers['set-cookie']?.[0]?.includes('SameSite=Lax'))
  })

  void it('POST update username without CSRF token is rejected', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'http://htmledit.squarefree.com')
      .type('form')
      .send({ username: 'CSRF' })
      .redirects(0)

    assert.equal(res.status, 403)
  })

  void it('POST update username with invalid CSRF token is rejected', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: 'CSRF', csrfToken: '0'.repeat(64) })
      .redirects(0)

    assert.equal(res.status, 403)
  })
})
