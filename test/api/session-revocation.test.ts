/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const nextSecond = async () => { await new Promise(resolve => setTimeout(resolve, 1100)) }

void describe('session revocation', () => {
  void it('password change revokes all other sessions of the user but keeps the current one', async () => {
    await register(app, { email: 'revoke.change@juice-sh.op', password: 'oldPassword1' })
    const { token: stolenToken } = await login(app, { email: 'revoke.change@juice-sh.op', password: 'oldPassword1' })
    await nextSecond()
    const { token: currentToken } = await login(app, { email: 'revoke.change@juice-sh.op', password: 'oldPassword1' })
    assert.notEqual(stolenToken, currentToken)

    await request(app)
      .get('/rest/user/change-password?current=oldPassword1&new=newPassword1&repeat=newPassword1')
      .set({ Authorization: 'Bearer ' + currentToken })
      .expect(200)

    await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + stolenToken })
      .expect(401)

    const stolenChange = await request(app)
      .get('/rest/user/change-password?new=hijacked1&repeat=hijacked1')
      .set({ Authorization: 'Bearer ' + stolenToken })
    assert.notEqual(stolenChange.status, 200)

    await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + currentToken })
      .expect(200)

    await request(app)
      .get('/rest/user/change-password?current=newPassword1&new=newPassword2&repeat=newPassword2')
      .set({ Authorization: 'Bearer ' + currentToken })
      .expect(200)
  })

  void it('logout revokes the token', async () => {
    await register(app, { email: 'revoke.logout@juice-sh.op', password: 'somePassword1' })
    const { token } = await login(app, { email: 'revoke.logout@juice-sh.op', password: 'somePassword1' })

    await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + token })
      .expect(200)

    await request(app)
      .post('/rest/user/logout')
      .set({ Authorization: 'Bearer ' + token })
      .expect(204)

    await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + token })
      .expect(401)

    const whoami = await request(app)
      .get('/rest/user/whoami')
      .set('Cookie', `token=${token}`)
    assert.equal(whoami.body.user.id, undefined)

    const change = await request(app)
      .get('/rest/user/change-password?new=hijacked1&repeat=hijacked1')
      .set({ Authorization: 'Bearer ' + token })
    assert.notEqual(change.status, 200)
  })

  void it('logout also revokes a newer cookie token of the same user', async () => {
    await register(app, { email: 'revoke.cookie@juice-sh.op', password: 'somePassword1' })
    const { token } = await login(app, { email: 'revoke.cookie@juice-sh.op', password: 'somePassword1' })
    const { token: cookieToken } = await login(app, { email: 'revoke.cookie@juice-sh.op', password: 'somePassword1' })
    assert.notEqual(token, cookieToken)

    await request(app)
      .post('/rest/user/logout')
      .set({ Authorization: 'Bearer ' + token })
      .set('Cookie', `token=${cookieToken}`)
      .expect(204)

    await request(app)
      .get('/api/Complaints')
      .set({ Authorization: 'Bearer ' + cookieToken })
      .expect(401)
  })
})
