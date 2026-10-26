/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import config from 'config'
import { clientConfigurationAllowlist } from '../../routes/appConfiguration'
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

function leafPaths (obj: Record<string, any>, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([key, value]) =>
    value !== null && typeof value === 'object' && !Array.isArray(value)
      ? leafPaths(value, `${prefix}${key}.`)
      : [`${prefix}${key}`])
}

function assertOnlyAllowlisted (body: Record<string, any>) {
  for (const path of leafPaths(body)) {
    assert.ok(clientConfigurationAllowlist.includes(path), `unexpected setting ${path}`)
  }
  assert.equal(body.application.chatBot.llmApiUrl, undefined)
  assert.equal(body.products, undefined)
  assert.equal(body.memories, undefined)
  assert.equal(body.server, undefined)
  assert.equal(body.challenges.csafHashValue, undefined)
}

void describe('/rest/application-configuration', () => {
  void it('GET client configuration anonymously returns only allowlisted settings', async () => {
    const res = await request(app)
      .get('/rest/application-configuration')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.config.application.name, config.get<string>('application.name'))
    assert.equal(res.body.config.application.domain, config.get<string>('application.domain'))
    assertOnlyAllowlisted(res.body.config)
  })
})

void describe('/rest/admin/application-configuration', () => {
  void it('GET application configuration is denied for anonymous users', async () => {
    const res = await request(app)
      .get('/rest/admin/application-configuration')

    assert.equal(res.status, 401)
    assert.equal(res.body.config, undefined)
  })

  void it('GET application configuration is denied for customers', async () => {
    const { token } = await login(app, { email: `jim@${config.get<string>('application.domain')}`, password: 'ncc-1701' })
    const res = await request(app)
      .get('/rest/admin/application-configuration')
      .set('Authorization', `Bearer ${token}`)

    assert.equal(res.status, 403)
    assert.equal(res.body.config, undefined)
  })

  void it('GET application configuration as admin returns only allowlisted settings', async () => {
    const { token } = await login(app, { email: `admin@${config.get<string>('application.domain')}`, password: 'admin123' })
    const res = await request(app)
      .get('/rest/admin/application-configuration')
      .set('Authorization', `Bearer ${token}`)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assertOnlyAllowlisted(res.body.config)
  })
})
