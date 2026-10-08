/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import type { Sequelize } from 'sequelize'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let sequelize: Sequelize
let authHeader: { Cookie: string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  sequelize = result.sequelize
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

  void it('GET user profile renders username template syntax literally without evaluating it', async () => {
    const payloads = [
      "#{global.process.mainModule.require('child_process').execSync('id')}",
      "#{'ssti' + 'Marker' + 'Evaluated'}"
    ]
    for (const payload of payloads) {
      await request(app)
        .post('/profile')
        .set('Cookie', authHeader.Cookie)
        .field('username', payload)
        .redirects(0)

      const res = await request(app)
        .get('/profile')
        .set(authHeader)

      assert.equal(res.status, 200)
      assert.ok(res.text.includes(payload))
      assert.ok(!res.text.includes('uid='))
      assert.ok(!res.text.includes('sstiMarkerEvaluated'))
    }
  })

  void it('GET user profile HTML-escapes stored username markup', async () => {
    await sequelize.query('UPDATE Users SET username = ? WHERE email = ?', {
      replacements: ['<script>alert(1)</script>', 'jim@juice-sh.op']
    })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('&lt;script&gt;alert(1)&lt;/script&gt;'))
    assert.ok(!res.text.includes('<script>alert(1)</script>'))
  })
})
