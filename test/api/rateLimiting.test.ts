/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import { randomUUID } from 'node:crypto'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

const jsonHeader = { 'content-type': 'application/json' }

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const spoofedIp = (i: number) => `10.${Math.floor(i / 250)}.${i % 250}.${i % 7 + 1}`

void describe('/rest/user/reset-password rate limiting', () => {
  void it('POST ignores spoofed X-Forwarded-For and limits failed answers per account', async () => {
    const email = 'xff-rate-limit-probe@' + config.get<string>('application.domain')
    const statuses: number[] = []
    for (let i = 0; i < 11; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ ...jsonHeader, 'X-Forwarded-For': spoofedIp(i) })
        .send({ email, answer: 'guess' + i, new: 'abcdef', repeat: 'abcdef' })
      statuses.push(res.status)
    }

    assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401))
    assert.equal(statuses[10], 429)
  })
})

void describe('/rest/2fa/verify rate limiting', () => {
  void it('POST ignores spoofed X-Forwarded-For and limits failed TOTP codes per account', async () => {
    const tmpToken = security.authorize({
      userId: 4242,
      type: 'password_valid_needs_second_factor_token'
    })
    const statuses: number[] = []
    for (let i = 0; i < 11; i++) {
      const res = await request(app)
        .post('/rest/2fa/verify')
        .set({ ...jsonHeader, 'X-Forwarded-For': spoofedIp(i) })
        .send({ tmpToken, totpToken: String(100000 + i) })
      statuses.push(res.status)
    }

    assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401))
    assert.equal(statuses[10], 429)
  })
})

for (const endpoint of ['setup', 'disable']) {
  void describe(`/rest/2fa/${endpoint} rate limiting`, () => {
    void it('POST ignores spoofed X-Forwarded-For and limits failed password confirmations per account', async () => {
      const email = `xff-rate-limit-${endpoint}@bar.com`
      const password = randomUUID()
      await register(app, { email, password })
      const { token } = await login(app, { email, password })
      const statuses: number[] = []
      for (let i = 0; i < 11; i++) {
        const res = await request(app)
          .post(`/rest/2fa/${endpoint}`)
          .set({ ...jsonHeader, Authorization: 'Bearer ' + token, 'X-Forwarded-For': spoofedIp(i) })
          .send({ password: 'wrong' + i })
        statuses.push(res.status)
      }

      assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401))
      assert.equal(statuses[10], 429)
    })
  })
}
