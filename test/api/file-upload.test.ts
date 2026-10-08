/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import path from 'node:path'
import { challenges } from '../../data/datacache'
import * as utils from '../../lib/utils'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/file-upload', () => {
  void it('POST file valid PDF for client and API', async () => {
    const file = path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file too large for client validation but valid for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidSizeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file with illegal type for client validation but valid for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidTypeForClient.exe')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file type XML deprecated for API', async () => {
    const file = path.resolve(__dirname, '../files/deprecatedTypeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
  })

  void it('POST file type XML does not reflect parsed content', async () => {
    const file = path.resolve(__dirname, '../files/deprecatedTypeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('deprecated for security reasons'))
    assert.ok(!res.text.includes('B. Kimminich'))
  })

  void it('POST XML file larger than the XML size limit is rejected before parsing', async () => {
    const file = path.resolve(__dirname, '../files/maxSizeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('must not contain a DTD'))
    assert.ok(!res.text.includes('B. Kimminich'))
  })

  void it('POST file type XML with XXE attack against Windows is rejected', async () => {
    const file = path.resolve(__dirname, '../files/xxeForWindows.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('must not contain a DTD'))
    assert.ok(!res.text.includes('[fonts]'))
  })

  void it('POST file type XML with XXE attack against Linux is rejected', async () => {
    const file = path.resolve(__dirname, '../files/xxeForLinux.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('must not contain a DTD'))
    assert.ok(!res.text.includes('root:x:0:0'))
  })

  void it('POST file type XML with XXE attack encoded as UTF-16 is rejected', async () => {
    const payload = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    const res = await request(app)
      .post('/file-upload')
      .attach('file', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(payload, 'utf16le')]), 'xxeUtf16.xml')
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('must not contain a DTD'))
    assert.ok(!res.text.includes('root:x:0:0'))
  })

  void it('POST file type XML with XXE attack hidden behind a non-UTF-8 encoding declaration is rejected', async () => {
    const payload = '<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE foo +AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-<foo>&xxe;</foo>'
    const res = await request(app)
      .post('/file-upload')
      .attach('file', Buffer.from(payload), 'xxeUtf7.xml')
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('must not contain a DTD'))
    assert.ok(!res.text.includes('root:x:0:0'))
  })

  void it('POST file type XML with Billion Laughs attack is rejected', async () => {
    const file = path.resolve(__dirname, '../files/xxeBillionLaughs.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('must not contain a DTD'))
  })

  void it('POST file type XML with Quadratic Blowup attack is rejected', async () => {
    const file = path.resolve(__dirname, '../files/xxeQuadraticBlowup.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('must not contain a DTD'))
  })

  void it('POST file type XML with dev/random attack is rejected', async () => {
    const file = path.resolve(__dirname, '../files/xxeDevRandom.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('must not contain a DTD'))
  })

  if (utils.isChallengeEnabled(challenges.yamlBombChallenge)) {
    void it('POST file type YAML with Billion Laughs-style attack', async () => {
      const file = path.resolve(__dirname, '../files/yamlBomb.yml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.ok(res.status >= 410)
    })
  }

  void it('POST file too large for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidSizeForServer.pdf')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 500)
  })

  void it('POST zip file with directory traversal payload', async () => {
    const file = path.resolve(__dirname, '../files/arbitraryFileWrite.zip')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST zip file with password protection', async () => {
    const file = path.resolve(__dirname, '../files/passwordProtected.zip')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST valid file with tampered content length', { skip: 'Fails on CI/CD pipeline' }, async () => {
    const file = path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .set('Content-Length', '42')
      .attach('file', file)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Unexpected end of form'))
  })
})
