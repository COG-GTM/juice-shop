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

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/reset-password rate limiting', () => {
  void it('POST password reset is rate limited after 100 requests even with rotating X-Forwarded-For headers', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 101; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': `10.0.${Math.floor(i / 256)}.${i % 256}` })
        .send({
          email: 'jim@' + config.get<string>('application.domain'),
          answer: 'definitely-wrong',
          new: 'ncc-1701',
          repeat: 'ncc-1701'
        })
      statuses.push(res.status)
    }

    assert.ok(statuses.slice(0, 100).every(status => status !== 429))
    assert.equal(statuses[100], 429)
  })
})
