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
  void it('POST username longer than 255 characters is rejected', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: '#{'.repeat(128) })
      .redirects(0)

    assert.equal(res.status, 400)
  })

  void it('POST image URL longer than 255 characters is rejected', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', authHeader.Cookie)
      .field('imageUrl', ';script-src'.repeat(24))
      .redirects(0)

    assert.equal(res.status, 400)
  })

  void it('GET user profile stays fast with longest allowed image URL of repeated pattern starts', async () => {
    await request(app)
      .post('/profile/image/url')
      .set('Cookie', authHeader.Cookie)
      .field('imageUrl', ';script-src'.repeat(23))
      .redirects(0)
      .expect(302)

    const start = Date.now()
    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(Date.now() - start < 1000)
  })

  void it('GET user profile stays fast with longest allowed username of repeated pattern starts', async () => {
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: '#{'.repeat(127) })
      .redirects(0)
      .expect(302)

    const start = Date.now()
    await request(app)
      .get('/profile')
      .set(authHeader)

    assert.ok(Date.now() - start < 1000)
  })
  void it('POST registration with username longer than 255 characters is rejected', async () => {
    const res = await request(app)
      .post('/api/Users')
      .send({ email: 'long-username@juice-sh.op', password: 'kitten lesser pooch', passwordRepeat: 'kitten lesser pooch', username: '#{'.repeat(128) })

    assert.equal(res.status, 400)
  })
})
