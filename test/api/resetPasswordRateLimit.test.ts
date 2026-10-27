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
  void it('POST password reset rate limit cannot be bypassed by spoofing X-Forwarded-For', async () => {
    let lastStatus = 0
    for (let i = 0; i < 101; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': `192.168.${Math.floor(i / 256)}.${i % 256}` })
        .send({ email: `nobody${i}@` + config.get<string>('application.domain'), answer: 'x', new: 'abcdef', repeat: 'abcdef' })
      lastStatus = res.status
    }
    assert.equal(lastStatus, 429)
  })
})
