/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import { generateSync } from 'otplib'
import type { Express } from 'express'
import config from 'config'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { loadStaticUserData } from '../../data/staticData'
import { isPrivilegedRole } from '../../data/privilegedSeedPasswords'

let app: Express

before(async () => {
  delete process.env.JUICE_SHOP_DEMO_CREDENTIALS
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const domain = config.get<string>('application.domain')

void describe('seeded accounts without JUICE_SHOP_DEMO_CREDENTIALS', async () => {
  const privilegedUsers = (await loadStaticUserData()).filter(({ role, deletedFlag }) => isPrivilegedRole(role) && deletedFlag !== true)

  void it('seeds at least the admin and accounting accounts', () => {
    assert.ok(privilegedUsers.some(({ role }) => role === 'admin'))
    assert.ok(privilegedUsers.some(({ role }) => role === 'accounting'))
  })

  for (const { email, customDomain, password } of privilegedUsers) {
    const completeEmail = customDomain ? email : `${email}@${domain}`
    void it(`POST login rejects the static password of privileged account ${completeEmail}`, async () => {
      await request(app)
        .post('/rest/user/login')
        .set({ 'content-type': 'application/json' })
        .send({ email: completeEmail, password })
        .expect(401)
    })
  }

  void it('POST login still accepts the static password of customer accounts', async () => {
    await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: `jim@${domain}`, password: 'ncc-1701' })
      .expect(200)
  })

  void it('POST 2fa verify rejects a token generated from the static TOTP secret of privileged account wurstbrot', async () => {
    const wurstbrot = (await loadStaticUserData()).find(({ email }) => email === 'wurstbrot')
    assert.ok(wurstbrot?.totpSecret)

    const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token' })
    await request(app)
      .post('/rest/2fa/verify')
      .set({ 'content-type': 'application/json' })
      .send({ tmpToken, totpToken: generateSync({ secret: wurstbrot.totpSecret }) })
      .expect(401)
  })
})
