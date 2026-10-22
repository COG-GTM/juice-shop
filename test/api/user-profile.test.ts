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

  void it('POST update username from same origin is accepted', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'http://127.0.0.1')
      .set('Host', '127.0.0.1')
      .type('form')
      .send({ username: 'Localhorst' })
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST update username from foreign origin is rejected as CSRF', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'http://htmledit.squarefree.com')
      .type('form')
      .send({ username: 'CSRF' })
      .redirects(0)

    assert.equal(res.status, 403)
  })

  void it('POST update username with foreign referer is rejected as CSRF', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Referer', 'http://htmledit.squarefree.com/')
      .type('form')
      .send({ username: 'CSRF' })
      .redirects(0)

    assert.equal(res.status, 403)
  })

  void it('POST profile image URL from foreign origin is rejected as CSRF', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'https://evil.example')
      .field('imageUrl', 'https://evil.example/x.png')
      .redirects(0)

    assert.equal(res.status, 403)
  })

  void it('POST profile image file from foreign origin is rejected as CSRF', async () => {
    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'https://evil.example')
      .attach('file', Buffer.from('x'), 'x.jpg')
      .redirects(0)

    assert.equal(res.status, 403)
  })
})
