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
      .type('form')
      .send({ username: 'Localhorst' })
      .redirects(0)

    assert.equal(res.status, 302)
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    assert.equal(user?.username, 'Localhorst')
  })

  for (const payload of ['x#{7*7}', 'a!{7*7}', "x#{process.mainModule.require('child_process').execSync('id')}", 'x\n- global.juiceShopSstiProbe = 1', '<script>alert(1)</script>', 'a'.repeat(51)]) {
    void it(`POST rejects username ${JSON.stringify(payload).substring(0, 40)} without saving it`, async () => {
      const res = await request(app)
        .post('/profile')
        .set('Cookie', authHeader.Cookie)
        .type('form')
        .send({ username: payload })
        .redirects(0)

      assert.equal(res.status, 400)
      const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
      assert.notEqual(user?.username, payload)
    })
  }

  void it('POST rejects a non-string username', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .send({ username: ['a', 'b'] })
      .redirects(0)

    assert.equal(res.status, 400)
  })

  for (const payload of ['x#{7*7}', 'a!{7*7}', '#{7*7}', "x#{global.process.mainModule.require('child_process').execSync('id')}"]) {
    void it(`GET user profile renders stored username ${payload} as literal text`, async () => {
      const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
      await user?.update({ username: payload })

      const res = await request(app)
        .get('/profile')
        .set(authHeader)

      assert.equal(res.status, 200)
      assert.ok(res.text.includes('text-align: center;">' + payload.substring(0, 3)))
      assert.ok(!res.text.includes('>x49<'))
      assert.ok(!res.text.includes('>a49<'))
      assert.ok(!res.text.includes('>49<'))
      assert.ok(!res.text.includes('uid='))
    })
  }

  void it('GET user profile does not execute Pug code from a stored multi-line username', async () => {
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    await user?.update({ username: 'x\n                  - global.juiceShopSstiProbe = 1' })

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal((global as Record<string, unknown>).juiceShopSstiProbe, undefined)
    assert.ok(res.text.includes('- global.juiceShopSstiProbe = 1'))
  })
})
