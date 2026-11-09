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

async function updateUsername (username: string) {
  const res = await request(app)
    .post('/profile')
    .set(authHeader)
    .type('form')
    .send({ username })
    .redirects(0)

  assert.equal(res.status, 302)
  const setCookie = res.headers['set-cookie']
  const updatedTokenCookie = Array.isArray(setCookie)
    ? setCookie.find(cookie => cookie.startsWith('token='))?.split(';')[0]
    : setCookie?.split(';')[0]
  assert.ok(updatedTokenCookie)
  return updatedTokenCookie
}

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

  void it('renders username expressions as plain text', async () => {
    const cookie = await updateUsername('#{7*7}')
    const res = await request(app)
      .get('/profile')
      .set('Cookie', cookie)

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('#{7*7}'))
    assert.ok(!res.text.includes('>49<'))
  })

  void it('escapes HTML in username', async () => {
    const cookie = await updateUsername('<script>alert(1)</script>')
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    assert.ok(user)
    user.setDataValue('username', '<script>alert(1)</script>')
    await user.save({ fields: ['username'] })
    const res = await request(app)
      .get('/profile')
      .set('Cookie', cookie)

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('&lt;script&gt;alert(1)&lt;/script&gt;'))
    assert.ok(!res.text.includes('<script>alert(1)</script>'))
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
