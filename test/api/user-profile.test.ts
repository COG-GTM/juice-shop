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

  void it('GET user profile renders a nested-tag username without a script tag', async () => {
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', '<<a|ascript>alert(`xss`)</script>')
      .redirects(0)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('<script>alert(`xss`)</script>'))
  })

  void it('GET user profile escapes HTML and template syntax in the username', async () => {
    const { UserModel } = await import('../../models/user')
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    await user?.update({ username: 'a&b #{7*7}' })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('a&amp;b #{7*7}'))
    assert.ok(!res.text.includes('a&b 49'))
  })

  void it('GET user profile CSP does not include directives injected via the profile image', async () => {
    const { UserModel } = await import('../../models/user')
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    await user?.update({ profileImage: "https://a.com/x.png; script-src 'unsafe-inline' 'self'" })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal(res.headers['content-security-policy'], "img-src 'self' https://a.com; script-src 'self' 'unsafe-eval'")
  })

  void it('GET user profile CSP only allows self for relative profile images', async () => {
    const { UserModel } = await import('../../models/user')
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    await user?.update({ profileImage: '/assets/public/images/uploads/default.svg' })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal(res.headers['content-security-policy'], "img-src 'self'; script-src 'self' 'unsafe-eval'")
  })
})
