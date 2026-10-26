/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import { generateSync } from 'otplib'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { createTestApp } from './helpers/setup'

const jsonHeader = { 'content-type': 'application/json' }

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const spoofedIp = (i: number) => `10.${Math.floor(i / 250)}.${i % 250}.${i % 7 + 1}`

void describe('/rest/user/reset-password rate limiting', () => {
  void it('POST ignores spoofed X-Forwarded-For and locks the account after 10 wrong answers', async () => {
    const email = 'morty@' + config.get<string>('application.domain')
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

    const correct = await request(app)
      .post('/rest/user/reset-password')
      .set({ ...jsonHeader, 'X-Forwarded-For': spoofedIp(99) })
      .send({ email: ' MORTY@' + config.get<string>('application.domain'), answer: '5N0wb41L', new: 'abcdef', repeat: 'abcdef' })
    assert.equal(correct.status, 429)
  })

  void it('POST for another account is not affected by the lockout', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({ email: 'jim@' + config.get<string>('application.domain'), answer: 'wrong', new: 'abcdef', repeat: 'abcdef' })
    assert.equal(res.status, 401)
  })
})

void describe('/rest/2fa/verify rate limiting', () => {
  void it('POST ignores spoofed X-Forwarded-For and locks the account after 10 wrong TOTP codes', async () => {
    const tmpToken = security.authorize({
      userId: 10,
      type: 'password_valid_needs_second_factor_token',
      expiresAt: security.secondFactorTokenExpiry()
    })
    const user = await UserModel.findByPk(10)
    const validTotp = generateSync({ secret: String(user?.totpSecret) })
    const wrongTotp = (i: number) => {
      const code = String(100000 + i)
      return code === validTotp ? String(200000 + i) : code
    }
    const statuses: number[] = []
    for (let i = 0; i < 11; i++) {
      const res = await request(app)
        .post('/rest/2fa/verify')
        .set({ ...jsonHeader, 'X-Forwarded-For': spoofedIp(i) })
        .send({ tmpToken, totpToken: wrongTotp(i) })
      statuses.push(res.status)
    }
    assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401))
    assert.equal(statuses[10], 429)

    const freshTmpToken = security.authorize({
      userId: 10,
      type: 'password_valid_needs_second_factor_token',
      expiresAt: security.secondFactorTokenExpiry()
    })
    const correct = await request(app)
      .post('/rest/2fa/verify')
      .set({ ...jsonHeader, 'X-Forwarded-For': spoofedIp(99) })
      .send({ tmpToken: freshTmpToken, totpToken: validTotp })
    assert.equal(correct.status, 429)
  })
})
