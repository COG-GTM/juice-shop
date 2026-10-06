/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import { createTestApp } from './helpers/setup'

const spoofedIp = (i: number) => `10.13.${Math.floor(i / 250)}.${i % 250}`

void describe('/rest/user/reset-password rate limiting', () => {
  void it('does not trust X-Forwarded-For when no proxy hops are configured', async () => {
    const { app } = await createTestApp()
    assert.equal(app.get('trust proxy'), false)
  })

  void it('limits a client to 100 requests per window even with a rotating X-Forwarded-For header', { timeout: 120000 }, async () => {
    const { app } = await createTestApp()
    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json' })
        .set('X-Forwarded-For', spoofedIp(i))
        .send({ email: `nobody${i}@` + config.get<string>('application.domain'), answer: 'guess', new: 'x', repeat: 'x' })
      assert.equal(res.status, 401)
    }

    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .set('X-Forwarded-For', spoofedIp(100))
      .send({ email: 'nobody100@' + config.get<string>('application.domain'), answer: 'guess', new: 'x', repeat: 'x' })
    assert.equal(res.status, 429)
  })

  void it('limits guesses against one account to 10 per window even with a rotating X-Forwarded-For header', { timeout: 60000 }, async () => {
    const { app } = await createTestApp()
    const email = 'morty@' + config.get<string>('application.domain')
    for (let i = 0; i < 10; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json' })
        .set('X-Forwarded-For', spoofedIp(i))
        .send({ email: i % 2 === 0 ? email : ` ${email.toUpperCase()}`, answer: 'guess' + i, new: 'x', repeat: 'x' })
      assert.equal(res.status, 401)
    }

    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .set('X-Forwarded-For', spoofedIp(10))
      .send({ email, answer: '5N0wb41L', new: 'iBurri3dMySe1fInTheB4ckyard!', repeat: 'iBurri3dMySe1fInTheB4ckyard!' })
    assert.equal(res.status, 429)
  })
})
