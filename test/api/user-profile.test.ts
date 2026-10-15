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

    assert.match(res.text, /name="csrf" value="[0-9a-f]{64}"/)
  })

  void it('POST update username of authenticated user', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: 'Localhorst', csrf: await csrfTokenFrom(authHeader) })
      .redirects(0)

    assert.equal(res.status, 302)
    assert.ok(res.headers['set-cookie']?.[0].includes('SameSite=Strict'))
  })

  void it('POST update username is rejected without CSRF token', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: 'CSRF' })
      .redirects(0)

    assert.equal(res.status, 403)
    assert.ok(!(await profileOf(authHeader)).includes('value="CSRF"'))
  })

  void it('POST update username is rejected with CSRF token of another session', async () => {
    const { token } = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: 'CSRF', csrf: await csrfTokenFrom({ Cookie: `token=${token}` }) })
      .redirects(0)

    assert.equal(res.status, 403)
  })

  void it('POST update username is rejected from a cross-site origin', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'http://htmledit.squarefree.com')
      .type('form')
      .send({ username: 'CSRF', csrf: await csrfTokenFrom(authHeader) })
      .redirects(0)

    assert.equal(res.status, 403)
    assert.ok(!(await profileOf(authHeader)).includes('value="CSRF"'))
  })
})

async function profileOf (header: { Cookie: string }) {
  const res = await request(app).get('/profile').set(header)
  return res.text
}

async function csrfTokenFrom (header: { Cookie: string }) {
  const match = (await profileOf(header)).match(/name="csrf" value="([0-9a-f]{64})"/)
  assert.ok(match)
  return match[1]
}
