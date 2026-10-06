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

  void it('GET user profile does not evaluate JavaScript embedded in the username', async () => {
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', "#{'ssti' + '-' + 'evaluated'}")
      .redirects(0)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('ssti-evaluated'))
    assert.ok(res.text.includes('#{&#39;ssti&#39; + &#39;-&#39; + &#39;evaluated&#39;}'))
    assert.notEqual(app.locals.abused_ssti_bug, true)
  })

  void it('GET user profile does not compile Pug markup embedded in the username', async () => {
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', 'x #[strong pug-injected]')
      .redirects(0)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('<strong>pug-injected</strong>'))
    assert.ok(res.text.includes('x #[strong pug-injected]'))
  })

  void it('GET user profile does not copy profileImage directives into the CSP header', async (t) => {
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    const originalProfileImage = user?.profileImage
    await user?.update({ profileImage: "https://a.png; script-src 'unsafe-inline' 'self'" })
    t.after(async () => { await user?.update({ profileImage: originalProfileImage }) })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    const csp = res.headers['content-security-policy']
    assert.ok(!csp.includes("'unsafe-inline'"))
    assert.equal(csp, "img-src 'self'; script-src 'self' 'unsafe-eval'")
  })

  void it('GET user profile allows the origin of an external profileImage in the CSP header', async (t) => {
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    const originalProfileImage = user?.profileImage
    await user?.update({ profileImage: 'https://www.gravatar.com/avatar/abc' })
    t.after(async () => { await user?.update({ profileImage: originalProfileImage }) })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal(res.headers['content-security-policy'], "img-src 'self' https://www.gravatar.com; script-src 'self' 'unsafe-eval'")
  })

  void it('GET user profile allows a bracketed IPv6 profileImage origin in the CSP header', async (t) => {
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    const originalProfileImage = user?.profileImage
    await user?.update({ profileImage: 'http://[2001:db8::1]:8080/avatar.png' })
    t.after(async () => { await user?.update({ profileImage: originalProfileImage }) })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal(res.headers['content-security-policy'], "img-src 'self' http://[2001:db8::1]:8080; script-src 'self' 'unsafe-eval'")
  })
})
