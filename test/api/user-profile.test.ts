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

  void it('GET user profile renders template syntax in username as literal text', async () => {
    const payloads = [
      { username: 'a#{7*7}', expected: 'a#{7*7}' },
      { username: "#{global.process.mainModule.require('child_process').execSync('id')}", expected: '.execSync(' },
      { username: "x\n- throw new Error('pug')", expected: '- throw new Error(' }
    ]
    for (const { username, expected } of payloads) {
      const update = await request(app)
        .post('/profile')
        .set('Cookie', authHeader.Cookie)
        .type('form')
        .send({ username })
        .redirects(0)
      assert.equal(update.status, 302)

      const res = await request(app)
        .get('/profile')
        .set(authHeader)

      assert.equal(res.status, 200)
      assert.ok(res.text.includes(expected))
      assert.ok(!res.text.includes('a49'))
      assert.ok(!res.text.includes('uid='))
    }
  })
})
