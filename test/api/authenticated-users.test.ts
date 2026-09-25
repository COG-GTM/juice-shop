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
let authHeader: Record<string, string>
let customerAuthHeader: Record<string, string>

before(async () => {
  const result = await createTestApp()
  app = result.app

  const domain = config.get<string>('application.domain')
  const admin = await login(app, { email: `admin@${domain}`, password: 'admin123' })
  const customer = await login(app, { email: `bender@${domain}`, password: 'OhG0dPlease1nsertLiquor!' })
  authHeader = { Authorization: `Bearer ${admin.token}`, 'content-type': 'application/json' }
  customerAuthHeader = { Authorization: `Bearer ${customer.token}`, 'content-type': 'application/json' }
}, { timeout: 60000 })

void describe('/rest/user/authentication-details', () => {
  void it('GET all users with password replaced by asterisks', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(authHeader)

    assert.equal(res.status, 200)
    const userWithAsterisks = res.body.data.find((user: any) => user.password === '********************************')
    assert.ok(userWithAsterisks, 'Expected at least one user with password replaced by asterisks')
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

  void it('GET is forbidden for authenticated non-admin users', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(customerAuthHeader)

    assert.equal(res.status, 403)
  })

  void it('GET is forbidden without an authorization header', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')

    assert.equal(res.status, 401)
  })
})
