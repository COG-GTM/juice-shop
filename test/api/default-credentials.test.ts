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
import { challenges } from '../../data/datacache'

let app: Express

before(async () => {
  delete process.env.JUICE_SHOP_DEMO_CREDENTIALS
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const domain = config.get<string>('application.domain')

void describe('seeded accounts without JUICE_SHOP_DEMO_CREDENTIALS', async () => {
  const seededUsers = (await loadStaticUserData()).filter(({ deletedFlag }) => deletedFlag !== true)

  void it('covers the admin, accounting and demo accounts', () => {
    assert.ok(seededUsers.some(({ email }) => email === 'admin'))
    assert.ok(seededUsers.some(({ email }) => email === 'accountant'))
    assert.ok(seededUsers.some(({ email }) => email === 'demo'))
  })

  for (const { email, customDomain, password } of seededUsers) {
    const completeEmail = customDomain ? email : `${email}@${domain}`
    void it(`POST login rejects the static password of seeded account ${completeEmail}`, async () => {
      await request(app)
        .post('/rest/user/login')
        .set({ 'content-type': 'application/json' })
        .send({ email: completeEmail, password })
        .expect(401)
    })
  }

  void it('does not solve credential challenges for accounts whose static password was rejected', async () => {
    await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: `admin@${domain}`, password: 'admin123' })
      .expect(401)
    await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: `amy@${domain}`, password: 'K1f.....................' })
      .expect(401)
    assert.equal(challenges.weakPasswordChallenge.solved, false)
    assert.equal(challenges.loginAmyChallenge.solved, false)
  })

  void it('POST login still allows the SQL injection login challenge without a password', async () => {
    await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: `admin@${domain}'--`, password: 'irrelevant' })
      .expect(200)
  })

  void it('POST 2fa verify rejects a token generated from the static TOTP secret of account wurstbrot', async () => {
    const wurstbrot = (await loadStaticUserData()).find(({ email }) => email === 'wurstbrot')
    assert.ok(wurstbrot?.totpSecret)

    const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token' })
    await request(app)
      .post('/rest/2fa/verify')
      .set({ 'content-type': 'application/json' })
      .send({ tmpToken, totpToken: generateSync({ secret: wurstbrot.totpSecret }) })
      .expect(401)
  })

  for (const { email, customDomain, securityQuestion } of seededUsers.filter(({ securityQuestion }) => securityQuestion != null)) {
    const completeEmail = customDomain ? email : `${email}@${domain}`
    void it(`POST reset-password rejects the static security answer of seeded account ${completeEmail}`, async () => {
      await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json' })
        .send({ email: completeEmail, answer: securityQuestion?.answer, new: 'hijacked123', repeat: 'hijacked123' })
        .expect(401)
    })
  }

  void it('does not solve the reset password challenge of admin bjoern whose static security answer was rejected', async () => {
    await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ email: `bjoern@${domain}`, answer: 'West-2082', new: 'hijacked123', repeat: 'hijacked123' })
      .expect(401)
    assert.equal(challenges.resetPasswordBjoernChallenge.solved, false)
  })
})
