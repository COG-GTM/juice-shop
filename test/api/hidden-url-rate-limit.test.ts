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

const premiumUrl = '/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us'
const easterEggUrl = '/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg'
const privacyPolicyProofUrl = '/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility'

void describe('Hidden URL rate limiting', () => {
  void it('allows 100 requests per window and rejects further ones with 429 across all hidden URLs', async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app).get(premiumUrl)
      assert.equal(res.status, 200, `request ${i + 1} should succeed`)
    }
    const premium = await request(app).get(premiumUrl)
    assert.equal(premium.status, 429)
    assert.notEqual(premium.headers['content-type'], 'image/jpeg')

    const easterEgg = await request(app).get(easterEggUrl)
    assert.equal(easterEgg.status, 429)

    const privacyPolicyProof = await request(app).get(privacyPolicyProofUrl)
    assert.equal(privacyPolicyProof.status, 429)
  })
})
