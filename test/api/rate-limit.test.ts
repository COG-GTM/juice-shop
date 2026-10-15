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

const spoofedIp = (i: number) => `10.${Math.floor(i / 65536) % 256}.${Math.floor(i / 256) % 256}.${i % 256}`

void describe('rate limiting with spoofed X-Forwarded-For', () => {
  void it('POST password reset is throttled after 100 requests despite rotating X-Forwarded-For', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 101; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': spoofedIp(i) })
        .send({ email: 'morty@' + config.get<string>('application.domain'), answer: `guess${i}`, new: 'x', repeat: 'x' })
      statuses.push(res.status)
    }
    assert.ok(statuses.slice(0, 100).every(status => status !== 429))
    assert.equal(statuses[100], 429)
  })

  void it('POST 2FA verification is throttled after 100 requests despite rotating X-Forwarded-For', async () => {
    let last = 0
    for (let i = 0; i < 101; i++) {
      const res = await request(app)
        .post('/rest/2fa/verify')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': spoofedIp(i) })
        .send({ tmpToken: 'invalid', totpToken: String(i).padStart(6, '0') })
      last = res.status
    }
    assert.equal(last, 429)
  })

  void it('POST login is not throttled for successful logins', async () => {
    for (let i = 0; i < 12; i++) {
      await request(app)
        .post('/rest/user/login')
        .set({ 'content-type': 'application/json' })
        .send({ email: 'jim@' + config.get<string>('application.domain'), password: 'ncc-1701' })
        .expect(200)
    }
  })

  void it('POST login is not throttled for correct-password logins of 2FA users', async () => {
    for (let i = 0; i < 12; i++) {
      const res = await request(app)
        .post('/rest/user/login')
        .set({ 'content-type': 'application/json' })
        .send({ email: 'wurstbrot@' + config.get<string>('application.domain'), password: 'EinBelegtesBrotMitSchinkenSCHINKEN!' })
        .expect(401)
      assert.equal(res.body.status, 'totp_token_required')
    }
  })

  void it('POST login is throttled after 10 failed attempts despite rotating X-Forwarded-For', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 11; i++) {
      const res = await request(app)
        .post('/rest/user/login')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': spoofedIp(i) })
        .send({ email: 'admin@' + config.get<string>('application.domain'), password: `wrong${i}` })
      statuses.push(res.status)
    }
    assert.ok(statuses.slice(0, 10).every(status => status === 401))
    assert.equal(statuses[10], 429)
  })
})
