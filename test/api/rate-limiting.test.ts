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
const domain = config.get<string>('application.domain')
const spoofedIp = (i: number) => `10.0.${Math.floor(i / 256)}.${i % 256}`

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function statusesOf (count: number, path: string, body: (i: number) => object) {
  const statuses: number[] = []
  for (let i = 0; i < count; i++) {
    const res = await request(app)
      .post(path)
      .set({ ...jsonHeader, 'X-Forwarded-For': spoofedIp(i) })
      .send(body(i))
    statuses.push(res.status)
  }
  return statuses
}

void describe('rate limiting ignores spoofed X-Forwarded-For', () => {
  void it('POST password reset is blocked after 10 wrong answers for one account', async () => {
    const statuses = await statusesOf(11, '/rest/user/reset-password', i => ({ email: `morty@${domain}`, answer: `guess${i}`, new: 'x', repeat: 'x' }))
    assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401))
    assert.equal(statuses[10], 429)
  })

  void it('POST 2FA verification is blocked after 10 wrong tokens for one account', async () => {
    const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token' })
    const statuses = await statusesOf(11, '/rest/2fa/verify', i => ({ tmpToken, totpToken: String(i).padStart(6, '0') }))
    assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401))
    assert.equal(statuses[10], 429)
  })

  void it('POST login does not count successful logins', async () => {
    const statuses = await statusesOf(12, '/rest/user/login', () => ({ email: `jim@${domain}`, password: 'ncc-1701' }))
    assert.deepEqual(statuses, Array(12).fill(200))
  })

  void it('POST login does not count correct passwords of 2FA users', async () => {
    const statuses = await statusesOf(12, '/rest/user/login', () => ({ email: `wurstbrot@${domain}`, password: 'EinBelegtesBrotMitSchinkenSCHINKEN!' }))
    assert.deepEqual(statuses, Array(12).fill(401))
  })

  void it('POST login is blocked after 10 wrong passwords for one account', async () => {
    const statuses = await statusesOf(11, '/rest/user/login', i => ({ email: `admin@${domain}`, password: `wrong${i}` }))
    assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401))
    assert.equal(statuses[10], 429)
  })

  void it('POST login is blocked after 100 failed attempts from one client across accounts', async () => {
    const statuses = await statusesOf(101, '/rest/user/login', i => ({ email: `nobody${i}@${domain}`, password: 'wrong' }))
    assert.ok(statuses.includes(401))
    assert.ok(statuses.every(status => status === 401 || status === 429))
    assert.equal(statuses[100], 429)
  })
})
