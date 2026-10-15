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
let userId: number

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token, bid } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  authHeader = { Cookie: `token=${token}` }
  userId = bid
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
})

void describe('/profile Content-Security-Policy', () => {
  const injection = "https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'"

  void it('GET user profile ignores CSP directives injected via profile image', async () => {
    await UserModel.update({ profileImage: injection }, { where: { id: userId } })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal(res.headers['content-security-policy'], "img-src 'self'; script-src 'self' 'unsafe-eval'")
  })

  void it('GET user profile allows only the origin of an external profile image', async () => {
    await UserModel.update({ profileImage: "https://example.com/;script-src%20'unsafe-inline'/cat.png" }, { where: { id: userId } })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.headers['content-security-policy'], "img-src 'self' https://example.com; script-src 'self' 'unsafe-eval'")
  })

  void it('POST profile image URL does not persist a URL containing CSP directives', async () => {
    await UserModel.update({ profileImage: '/assets/public/images/uploads/default.svg' }, { where: { id: userId } })

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', authHeader.Cookie)
      .field('imageUrl', injection)
      .redirects(0)

    assert.equal(res.status, 302)
    const user = await UserModel.findByPk(userId)
    assert.equal(user?.profileImage, '/assets/public/images/uploads/default.svg')
  })
})
