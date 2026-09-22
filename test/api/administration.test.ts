/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as utils from '../../lib/utils'
import { exposedConfigPaths } from '../../routes/appConfiguration'

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
    assert.equal(res.body.config.application.name, 'OWASP Juice Shop')
  })

  void it('GET application configuration exposes only allowlisted properties', async () => {
    const res = await request(app)
      .get('/rest/admin/application-configuration')

    assert.equal(res.status, 200)
    assert.equal(res.body.config.application.chatBot.llmApiUrl, undefined)
    assert.equal(res.body.config.application.chatBot.model, undefined)
    assert.equal(res.body.config.products, undefined)
    assert.equal(res.body.config.memories, undefined)
    assert.equal(res.body.config.challenges.csafHashValue, undefined)
    assert.equal(res.body.config.server.basePath, undefined)

    const leafPaths = (value: unknown, prefix = ''): string[] => {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return [prefix]
      }
      return Object.entries(value).flatMap(([key, child]) => leafPaths(child, prefix !== '' ? `${prefix}.${key}` : key))
    }

    for (const path of leafPaths(res.body.config)) {
      assert.ok(exposedConfigPaths.includes(path), `unexpected configuration property ${path}`)
    }
  })
})
