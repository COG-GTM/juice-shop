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
  void it('cannot be bypassed by spoofing the X-Forwarded-For header', async () => {
    const statuses: number[] = []
    for (let i = 0; i <= 100; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': `10.0.${Math.floor(i / 256)}.${i % 256}` })
        .send({
          email: 'morty@' + config.get<string>('application.domain'),
          answer: 'wrong' + i,
          new: '12345',
          repeat: '12345'
        })
      statuses.push(res.status)
    }

    assert.ok(statuses.slice(0, 100).every(status => status === 401))
    assert.equal(statuses[100], 429)
  })
})
