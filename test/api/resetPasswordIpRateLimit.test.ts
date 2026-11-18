/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/reset-password client rate limiting', () => {
  void it('POST answers the 101st attempt with 429 even when every request spoofs a new X-Forwarded-For', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 101; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': `203.0.${Math.floor(i / 250)}.${i % 250 + 1}` })
        .send({ email: `mallory${i}@example.com`, answer: 'guess', new: 'abcdef', repeat: 'abcdef' })
      statuses.push(res.status)
    }
    assert.deepEqual(statuses.slice(0, 100), Array(100).fill(401))
    assert.equal(statuses[100], 429)
  })
})

void describe('/rest/2fa/verify client rate limiting', () => {
  void it('POST answers the 101st attempt with 429 even when every request spoofs a new X-Forwarded-For', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 101; i++) {
      const tmpToken = security.authorize({
        userId: 100000 + i,
        type: 'password_valid_needs_second_factor_token',
        expiresAt: Date.now() + 5 * 60 * 1000
      })
      const res = await request(app)
        .post('/rest/2fa/verify')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': `198.51.${Math.floor(i / 250)}.${i % 250 + 1}` })
        .send({ tmpToken, totpToken: '123456' })
      statuses.push(res.status)
    }
    assert.deepEqual(statuses.slice(0, 100), Array(100).fill(401))
    assert.equal(statuses[100], 429)
  })
})
