/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function register (email: string, password: string) {
  await request(app)
    .post('/api/Users')
    .set({ 'content-type': 'application/json' })
    .send({ email, password, passwordRepeat: password })
    .expect(201)
}

async function login (email: string, password: string, headers: Record<string, string> = {}) {
  return await request(app)
    .post('/rest/user/login')
    .set({ 'content-type': 'application/json', ...headers })
    .send({ email, password })
}

void describe('/rest/user/login rate limiting', () => {
  void it('locks an account after 10 failed logins, even for the correct password', { timeout: 60000 }, async () => {
    await register('lockout@rate.limit', 'correct-horse')

    for (let i = 0; i < 10; i++) {
      const res = await login('lockout@rate.limit', `wrong-${i}`)
      assert.equal(res.status, 401)
    }

    const locked = await login('lockout@rate.limit', 'correct-horse')
    assert.equal(locked.status, 429)
    assert.ok(Number(locked.headers['retry-after']) > 0)
  })

  void it('shares the lockout across email case and whitespace variants', { timeout: 60000 }, async () => {
    for (let i = 0; i < 10; i++) {
      const res = await login(i % 2 === 0 ? 'Variant@Rate.Limit' : '  variant@rate.limit ', 'wrong')
      assert.equal(res.status, 401)
    }

    const res = await login('VARIANT@RATE.LIMIT', 'wrong')
    assert.equal(res.status, 429)
  })

  void it('does not lock other accounts', async () => {
    await register('unaffected@rate.limit', 'still-works')

    const res = await login('unaffected@rate.limit', 'still-works')
    assert.equal(res.status, 200)
  })

  void it('resets the account counter after a successful login', { timeout: 60000 }, async () => {
    await register('reset@rate.limit', 'right-password')

    for (let i = 0; i < 9; i++) {
      assert.equal((await login('reset@rate.limit', 'wrong')).status, 401)
    }
    assert.equal((await login('reset@rate.limit', 'right-password')).status, 200)
    for (let i = 0; i < 9; i++) {
      assert.equal((await login('reset@rate.limit', 'wrong')).status, 401)
    }
    assert.equal((await login('reset@rate.limit', 'right-password')).status, 200)
  })

  void it('throttles a client after 100 failed logins across accounts and ignores X-Forwarded-For rotation', { timeout: 120000 }, async () => {
    let attempts = 0
    let status = 401
    while (status === 401 && attempts <= 100) {
      status = (await login(`spray-${attempts}@rate.limit`, 'Summer2026!', { 'X-Forwarded-For': `203.0.113.${attempts}` })).status
      attempts++
    }
    assert.equal(status, 429)

    const rotated = await login('unaffected@rate.limit', 'still-works', { 'X-Forwarded-For': '198.51.100.1' })
    assert.equal(rotated.status, 429)
  })
})
