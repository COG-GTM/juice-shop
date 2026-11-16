/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'
import { isPasswordChangeRequired } from '../../lib/passwordRotation'

const jsonHeader = { 'content-type': 'application/json' }
const adminEmail = () => 'admin@' + config.get<string>('application.domain')
const initialPassword = 'Initial-Test-Password-1'
const rotatedPassword = 'Rotated-Test-Password-2'

let app: Express

before(async () => {
  delete process.env.JUICE_SHOP_ADMIN_PASSWORD
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function adminUser () {
  const user = await UserModel.findOne({ where: { email: adminEmail() } })
  assert.ok(user)
  return user
}

async function requestRotationToken (password: string) {
  const res = await request(app).post('/rest/user/login').set(jsonHeader).send({ email: adminEmail(), password })
  assert.equal(res.status, 401)
  assert.equal(res.body.status, 'password_change_required')
  return res.body.data.tmpToken as string
}

void describe('initial administrator credential', () => {
  void it('is randomly generated and flagged for rotation when JUICE_SHOP_ADMIN_PASSWORD is not set', async () => {
    const user = await adminUser()
    assert.equal(isPasswordChangeRequired(user.id), true)
    assert.notEqual(user.password, security.hash('admin123'))
  })

  void it('rejects the former hardcoded admin password', async () => {
    const res = await request(app).post('/rest/user/login').set(jsonHeader).send({ email: adminEmail(), password: 'admin123' })
    assert.equal(res.status, 401)
    assert.equal(res.body.authentication, undefined)
  })

  void it('does not issue a session token before the initial password is rotated', async () => {
    const user = await adminUser()
    await user.update({ password: initialPassword })

    const res = await request(app).post('/rest/user/login').set(jsonHeader).send({ email: adminEmail(), password: initialPassword })
    assert.equal(res.status, 401)
    assert.equal(res.body.status, 'password_change_required')
    assert.equal(typeof res.body.data.tmpToken, 'string')
    assert.equal(res.body.authentication, undefined)
  })

  void it('rejects rotation with a token of another type', async () => {
    const user = await adminUser()
    const tmpToken = security.authorize({ userId: user.id, type: 'password_valid_needs_second_factor_token' })
    const res = await request(app).post('/rest/user/rotate-initial-password').set(jsonHeader).send({ tmpToken, new: rotatedPassword, repeat: rotatedPassword })
    assert.equal(res.status, 401)
  })

  void it('rejects rotation with a stale rotation token', async () => {
    const user = await adminUser()
    const tmpToken = security.authorize({ userId: user.id, type: 'password_valid_needs_rotation' })
    const now = Date.now()
    const clock = mock.method(Date, 'now', () => now + 60 * 60 * 1000)
    try {
      const res = await request(app).post('/rest/user/rotate-initial-password').set(jsonHeader).send({ tmpToken, new: rotatedPassword, repeat: rotatedPassword })
      assert.equal(res.status, 401)
    } finally {
      clock.mock.restore()
    }
    assert.ok(isPasswordChangeRequired(user.id))
  })

  void it('rejects rotation to a short, mismatching or unchanged password', async () => {
    const tmpToken = await requestRotationToken(initialPassword)
    for (const [newPassword, repeat] of [['short', 'short'], [rotatedPassword, rotatedPassword + 'x'], [initialPassword, initialPassword]]) {
      const res = await request(app).post('/rest/user/rotate-initial-password').set(jsonHeader).send({ tmpToken, new: newPassword, repeat })
      assert.equal(res.status, 400)
    }
    assert.equal(isPasswordChangeRequired((await adminUser()).id), true)
  })

  void it('rotates the initial password and allows regular login afterwards', async () => {
    const tmpToken = await requestRotationToken(initialPassword)
    const res = await request(app).post('/rest/user/rotate-initial-password').set(jsonHeader).send({ tmpToken, new: rotatedPassword, repeat: rotatedPassword })
    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(isPasswordChangeRequired((await adminUser()).id), false)

    const replay = await request(app).post('/rest/user/rotate-initial-password').set(jsonHeader).send({ tmpToken, new: 'Another-Test-Password-3', repeat: 'Another-Test-Password-3' })
    assert.equal(replay.status, 401)

    const oldLogin = await request(app).post('/rest/user/login').set(jsonHeader).send({ email: adminEmail(), password: initialPassword })
    assert.equal(oldLogin.status, 401)

    const newLogin = await request(app).post('/rest/user/login').set(jsonHeader).send({ email: adminEmail(), password: rotatedPassword })
    assert.equal(newLogin.status, 200)
    assert.equal(typeof newLogin.body.authentication.token, 'string')
  })
})
