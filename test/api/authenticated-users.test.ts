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
const authHeader = { Authorization: `Bearer ${security.authorize({ data: { email: 'admin@juice-sh.op' } })}`, 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/authentication-details', () => {
  void it('GET all users returns only id, email and lastLoginTime', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 1)
    for (const user of res.body.data) {
      assert.deepEqual(Object.keys(user).sort(), ['email', 'id', 'lastLoginTime'])
    }
  })

  void it('GET all users ordered by id when no limit is given', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set(authHeader)

    const ids = res.body.data.map((user: any) => user.id)
    assert.deepEqual(ids, [...ids].sort((a: number, b: number) => a - b))
  })

  void it('GET users page with limit and offset', async () => {
    const all = await request(app)
      .get('/rest/user/authentication-details')
      .set(authHeader)
    const page = await request(app)
      .get('/rest/user/authentication-details?limit=2&offset=1')
      .set(authHeader)

    assert.equal(page.status, 200)
    assert.deepEqual(page.body.data.map((user: any) => user.id), all.body.data.slice(1, 3).map((user: any) => user.id))
  })

  void it('GET users page with huge offset returns an empty page', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details?limit=2&offset=100000000000000000000')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('GET users page size is capped', async () => {
    const res = await request(app)
      .get('/rest/user/authentication-details?limit=100000')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.body.data.length <= 100)
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
