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
let adminToken: string
const authHeader = () => ({ Authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' })

before(async () => {
  const result = await createTestApp()
  app = result.app
  const admin = await login(app, {
    email: `admin@${config.get<string>('application.domain')}`,
    password: 'admin123'
  })
  adminToken = admin.token
}, { timeout: 60000 })

void describe('/rest/user/authentication-details', () => {
  void it('GET all users with sensitive fields removed and password replaced by asterisks', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(authHeader())

    assert.equal(res.status, 200)
    const userWithAsterisks = res.body.data.find((user: any) => user.password === '********************************')
    assert.ok(userWithAsterisks, 'Expected at least one user with password replaced by asterisks')
    assert.ok(res.body.data.every((user: any) => !('deluxeToken' in user)))
    assert.ok(res.body.data.every((user: any) => !('lastLoginIp' in user)))
  })

  void it('GET returns lastLoginTime for users with active sessions', async () => {
    await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(authHeader())

    assert.equal(res.status, 200)

    const jim = res.body.data.find((user: any) => user.email.startsWith('jim@'))
    assert.ok(jim, 'Expected to find jim in the user list')
    assert.equal(typeof jim.lastLoginTime, 'number')
  })

  void it('denies customers', async () => {
    const customer = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set({ Authorization: `Bearer ${customer.token}` })

    assert.equal(res.status, 403)
  })

  void it('checks the database role instead of the token role claim', async () => {
    const jim = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const jimPayload = security.decode(jim.token) as { data: { id: number } }
    const tokenWithAdminClaim = security.authorize({
      data: { id: jimPayload.data.id, role: 'admin' }
    })

    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set({ Authorization: `Bearer ${tokenWithAdminClaim}` })

    assert.equal(res.status, 403)
  })

  void it('rejects unsigned alg:none tokens', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({
      data: { id: 1, email: `admin@${config.get<string>('application.domain')}`, role: 'admin' }
    })).toString('base64url')

    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set({ Authorization: `Bearer ${header}.${payload}.` })

    assert.equal(res.status, 403)
    assert.equal(res.body.error, 'Malicious activity detected')
  })

  void it('requires an authorization header', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')

    assert.equal(res.status, 401)
  })
})
