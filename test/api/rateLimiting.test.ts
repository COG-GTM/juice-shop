/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

const jsonHeader = { 'content-type': 'application/json' }
const spoofedIp = (i: number) => `10.13.${Math.floor(i / 250)}.${i % 250}`

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('rate limiting', () => {
  void it('does not trust X-Forwarded-For unless proxy hops are configured', () => {
    assert.equal(app.get('trust proxy'), false)
  })

  void it('POST /rest/2fa/verify is limited per account even with rotating X-Forwarded-For', { timeout: 60000 }, async () => {
    const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token' })
    for (let i = 0; i < 10; i++) {
      const res = await request(app).post('/rest/2fa/verify').set(jsonHeader).set('X-Forwarded-For', spoofedIp(i))
        .send({ tmpToken, totpToken: '000000' })
      assert.equal(res.status, 401)
    }
    const res = await request(app).post('/rest/2fa/verify').set(jsonHeader).set('X-Forwarded-For', spoofedIp(10))
      .send({ tmpToken, totpToken: '000000' })
    assert.equal(res.status, 429)
  })

  void it('POST /rest/user/reset-password is limited per account even with rotating X-Forwarded-For', { timeout: 60000 }, async () => {
    const email = 'morty@' + config.get<string>('application.domain')
    for (let i = 0; i < 10; i++) {
      const res = await request(app).post('/rest/user/reset-password').set(jsonHeader).set('X-Forwarded-For', spoofedIp(i))
        .send({ email, answer: 'guess' + i, new: 'x', repeat: 'x' })
      assert.equal(res.status, 401)
    }
    const res = await request(app).post('/rest/user/reset-password').set(jsonHeader).set('X-Forwarded-For', spoofedIp(10))
      .send({ email, answer: '5N0wb41L', new: 'iBurri3dMySe1fInTheB4ckyard!', repeat: 'iBurri3dMySe1fInTheB4ckyard!' })
    assert.equal(res.status, 429)
  })

  void it('POST /rest/user/login is limited per client even with rotating X-Forwarded-For', { timeout: 120000 }, async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app).post('/rest/user/login').set(jsonHeader).set('X-Forwarded-For', spoofedIp(i))
        .send({ email: 'admin@' + config.get<string>('application.domain'), password: 'wrong' + i })
      assert.equal(res.status, 401)
    }
    const res = await request(app).post('/rest/user/login').set(jsonHeader).set('X-Forwarded-For', spoofedIp(100))
      .send({ email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
    assert.equal(res.status, 429)
  })
})
