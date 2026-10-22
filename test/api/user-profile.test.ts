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
import { UserModel } from '../../models/user'

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

  void it('GET user profile renders the username escaped and keeps the CSP intact for injected profile images', async () => {
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    assert.ok(user)
    const { username, profileImage } = user
    await user.update({ username: '<<a|ascript>alert(`xss`)</script>', profileImage: "https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'" })

    try {
      const res = await request(app)
        .get('/profile')
        .set(authHeader)

      assert.equal(res.status, 200)
      assert.equal(res.headers['content-security-policy'], "img-src 'self'; script-src 'self' 'unsafe-eval'")
      assert.ok(!res.text.includes('<script>alert(`xss`)</script>'))
      assert.ok(res.text.includes('&lt;script&gt;alert(`xss`)&lt;/script&gt;'))
    } finally {
      await user.update({ username, profileImage })
    }
  })

  void it('GET user profile allows the origin of an absolute profile image URL in the CSP', async () => {
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    assert.ok(user)
    const { profileImage } = user
    await user.update({ profileImage: 'https://www.gravatar.com/avatar/abc' })

    try {
      const res = await request(app)
        .get('/profile')
        .set(authHeader)

      assert.equal(res.status, 200)
      assert.equal(res.headers['content-security-policy'], "img-src 'self' https://www.gravatar.com; script-src 'self' 'unsafe-eval'")
    } finally {
      await user.update({ profileImage })
    }
  })
})
