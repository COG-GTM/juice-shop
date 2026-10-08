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
const domain = config.get<string>('application.domain')

async function bearer (email: string, password: string) {
  const { token } = await login(app, { email, password })
  return { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/authentication-details', () => {
  void it('GET all users as admin returns only id, email and lastLoginTime', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(await bearer(`admin@${domain}`, 'admin123'))

    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 1)
    for (const user of res.body.data) {
      assert.deepEqual(Object.keys(user).sort(), ['email', 'id', 'lastLoginTime'])
    }
  })

  void it('GET returns lastLoginTime for users with active sessions', async () => {
    await login(app, {
      email: `jim@${domain}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(await bearer(`admin@${domain}`, 'admin123'))

    assert.equal(res.status, 200)

    const jim = res.body.data.find((user: any) => user.email.startsWith('jim@'))
    assert.ok(jim, 'Expected to find jim in the user list')
    assert.equal(typeof jim.lastLoginTime, 'number')
  })

  void it('GET all users is forbidden for customers', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(await bearer(`jim@${domain}`, 'ncc-1701'))

    assert.equal(res.status, 403)
    assert.equal(res.body.data, undefined)
  })

  void it('GET all users is forbidden without a token', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')

    assert.equal(res.status, 403)
    assert.equal(res.body.data, undefined)
  })
})
