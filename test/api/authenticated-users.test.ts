/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
const authHeader = { Authorization: `Bearer ${security.authorize({ data: { email: 'admin@juice-sh.op', role: security.roles.admin } })}`, 'content-type': 'application/json' }
const customerAuthHeader = { Authorization: `Bearer ${security.authorize({ data: { email: 'jim@juice-sh.op', role: security.roles.customer } })}`, 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/authentication-details', () => {
  void it('GET is denied without authentication', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')

    assert.equal(res.status, 401)
  })

  void it('GET is forbidden for non-admin users', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(customerAuthHeader)

    assert.equal(res.status, 403)
    assert.equal(res.body.data, undefined)
  })

  void it('GET is forbidden for a forged token claiming the admin role', async () => {
    const forged = security.authorize({ data: { email: 'jim@juice-sh.op', role: security.roles.admin } }).split('.')
    forged[2] = forged[2].split('').reverse().join('')
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set({ Authorization: `Bearer ${forged.join('.')}` })

    assert.notEqual(res.status, 200)
    assert.equal(res.body.data, undefined)
  })

  void it('GET all users returns only allowlisted fields for admins', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    for (const user of res.body.data) {
      assert.deepEqual(Object.keys(user).sort(), ['email', 'id', 'lastLoginTime'])
    }
  })

  void it('GET returns lastLoginTime for users with active sessions', async () => {
    await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(authHeader)

    assert.equal(res.status, 200)

    const jim = res.body.data.find((user: any) => user.email.startsWith('jim@'))
    assert.ok(jim, 'Expected to find jim in the user list')
    assert.equal(typeof jim.lastLoginTime, 'number')
  })
})
