/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import path from 'node:path'
import fs from 'node:fs'
import { challenges } from '../../data/datacache'
import * as utils from '../../lib/utils'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let jimHeader: { Authorization: string }
let benderHeader: { Authorization: string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  jimHeader = { Authorization: 'Bearer ' + (await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })).token }
  benderHeader = { Authorization: 'Bearer ' + (await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })).token }
}, { timeout: 60000 })

void describe('/file-upload resource limits', () => {
  void it('POST zip with a file name longer than the file system allows keeps the server running', async () => {
    const zip = fs.readFileSync(path.resolve(__dirname, '../files/validComplaint.zip'))
    const res = await request(app)
      .post('/file-upload')
      .set(jimHeader)
      .attach('file', zip, 'a'.repeat(300) + '.zip')
    assert.ok(res.status < 500, `unexpected status ${res.status}`)
    const after = await request(app)
      .post('/file-upload')
      .set(jimHeader)
      .attach('file', path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf'))
    assert.equal(after.status, 204)
  })

  void it('POST YAML alias bomb is rejected well before the 2s sandbox timeout', async () => {
    const started = Date.now()
    const res = await request(app)
      .post('/file-upload')
      .set(jimHeader)
      .attach('file', path.resolve(__dirname, '../files/yamlBomb.yml'))
    const elapsed = Date.now() - started
    assert.ok(res.status >= 410, `unexpected status ${res.status}`)
    assert.ok(elapsed < 1000, `took ${elapsed}ms`)
    if (utils.isChallengeEnabled(challenges.yamlBombChallenge)) {
      assert.equal(challenges.yamlBombChallenge.solved, true)
    }
  })

  void it('POST more than 100 files within 5 minutes from one user is rate limited without affecting other users', async () => {
    const pdf = path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf')
    for (let i = 0; i < 100; i++) {
      const res = await request(app).post('/file-upload').set(benderHeader).attach('file', pdf)
      assert.equal(res.status, 204, `upload ${i + 1} returned ${res.status}`)
    }
    const limited = await request(app).post('/file-upload').set(benderHeader).attach('file', pdf)
    assert.equal(limited.status, 429)
    const otherUser = await request(app).post('/file-upload').set(jimHeader).attach('file', pdf)
    assert.equal(otherUser.status, 204)
  })

  void it('POST file without authentication is still rejected with 401', async () => {
    const res = await request(app)
      .post('/file-upload')
      .attach('file', path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf'))
    assert.equal(res.status, 401)
  })
})
