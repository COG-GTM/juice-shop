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
})

void describe('/profile Content-Security-Policy', () => {
  let benderCookie: string

  before(async () => {
    const { token } = await login(app, {
      email: `bender@${config.get<string>('application.domain')}`,
      password: 'OhG0dPlease1nsertLiquor!'
    })
    benderCookie = `token=${token}`
  })

  async function setProfileImageUrl (imageUrl: string) {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', benderCookie)
      .field('imageUrl', imageUrl)
      .redirects(0)
    assert.equal(res.status, 302)
  }

  void it('does not let a profile image URL inject CSP directives', async () => {
    await setProfileImageUrl("https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'")

    const res = await request(app)
      .get('/profile')
      .set('Cookie', benderCookie)

    assert.equal(res.status, 200)
    assert.equal(res.headers['content-security-policy'], "img-src 'self'; script-src 'self' 'unsafe-eval'")
  })

  void it('allows only the origin of an absolute profile image URL in img-src', async () => {
    await setProfileImageUrl('http://127.0.0.1:1/avatar.png')

    const res = await request(app)
      .get('/profile')
      .set('Cookie', benderCookie)

    assert.equal(res.status, 200)
    assert.equal(res.headers['content-security-policy'], "img-src 'self' http://127.0.0.1:1; script-src 'self' 'unsafe-eval'")
  })
})
