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
const sameOrigin = { Host: 'localhost:3000', Origin: 'http://localhost:3000' }

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
      .set(sameOrigin)
      .type('form')
      .send({ username: 'Localhorst' })
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST username containing template or script syntax is rejected', async () => {
    for (const username of ["#{global.process.mainModule.require('child_process').execSync('id')}", '<script>alert(`xss`)</script>', 'a'.repeat(65)]) {
      const res = await request(app)
        .post('/profile')
        .set('Cookie', authHeader.Cookie)
        .set(sameOrigin)
        .type('form')
        .send({ username })
        .redirects(0)

      assert.equal(res.status, 400)
    }
  })

  void it('POST update username from a foreign origin is rejected', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'http://htmledit.squarefree.com')
      .type('form')
      .send({ username: 'CSRF' })
      .redirects(0)

    assert.equal(res.status, 403)
  })

  void it('POST update username without Origin or Referer is rejected', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: 'CSRF' })
      .redirects(0)

    assert.equal(res.status, 403)
  })

  void it('POST update username from the same host but another scheme is rejected', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Host', 'localhost:3000')
      .set('Origin', 'https://localhost:3000')
      .type('form')
      .send({ username: 'CSRF' })
      .redirects(0)

    assert.equal(res.status, 403)
  })

  void it('POST update username from the same origin via Referer is accepted', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Host', 'localhost:3000')
      .set('Referer', 'http://localhost:3000/profile')
      .type('form')
      .send({ username: 'Localhorst' })
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('GET user profile neither evaluates nor compiles a stored username', async () => {
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    assert.ok(user)
    await user.update({ username: '#{global.sstiProbe = 7*7}' })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal(Reflect.get(globalThis, 'sstiProbe'), undefined)
    assert.ok(res.text.includes('#{global.sstiProbe = 7*7}'))
    assert.ok(!res.text.includes('>49<'))
  })
})
