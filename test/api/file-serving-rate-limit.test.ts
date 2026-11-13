/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

const hiddenUrls = [
  '/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg',
  '/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us',
  '/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility'
]

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('Hidden URL rate limiting', () => {
  for (const url of hiddenUrls) {
    void it(`GET ${url} sends rate limit headers`, async () => {
      const res = await request(app).get(url)
      assert.notEqual(res.status, 429)
      assert.equal(res.headers['x-ratelimit-limit'], '60')
    })
  }

  void it('GET hidden URLs are blocked with 429 once the shared limit is exhausted', async () => {
    let lastStatus = 0
    for (let i = 0; i <= 60; i++) {
      lastStatus = (await request(app).get(hiddenUrls[i % hiddenUrls.length])).status
      if (lastStatus === 429) break
    }
    assert.equal(lastStatus, 429)
    for (const url of hiddenUrls) {
      const res = await request(app).get(url)
      assert.equal(res.status, 429)
    }
  })
})
