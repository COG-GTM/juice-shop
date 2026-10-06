/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import config from 'config'
import * as utils from '../../lib/utils'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/admin/application-version', () => {
  void it('GET application version from package.json', async () => {
    const res = await request(app)
      .get('/rest/admin/application-version')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.version, utils.version())
  })
})

void describe('/rest/admin/application-configuration', () => {
  void it('GET application configuration', async () => {
    const res = await request(app)
      .get('/rest/admin/application-configuration')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.config, 'object')
    assert.ok(res.body.config !== null)
    assert.equal(res.body.config.application.name, config.get<string>('application.name'))
    assert.equal(res.body.config.application.domain, config.get<string>('application.domain'))
  })

  void it('GET application configuration exposes only allowlisted settings', async () => {
    const res = await request(app)
      .get('/rest/admin/application-configuration')

    assert.equal(res.status, 200)
    const body = res.body.config
    assert.equal(body.application.chatBot.llmApiUrl, undefined)
    assert.equal(body.application.chatBot.model, undefined)
    assert.equal(body.application.customMetricsPrefix, undefined)
    assert.equal(body.server.basePath, undefined)
    assert.equal(body.server.baseUrl, undefined)
    assert.equal(body.challenges.csafHashValue, undefined)
    assert.equal(body.challenges.xssBonusPayload, undefined)
    assert.equal(body.challenges.metricsIgnoredUserAgents, undefined)
    assert.equal(body.products, undefined)
    assert.equal(body.memories, undefined)
  })
})
