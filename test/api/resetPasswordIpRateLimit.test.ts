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
