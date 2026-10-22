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
    assert.ok(!res.text.includes('Apple Juice'))
  })

  void it('POST large XML file near upload size limit', async () => {
    const file = path.resolve(__dirname, '../files/maxSizeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
  })

  if (utils.isChallengeEnabled(challenges.xxeFileDisclosureChallenge) || utils.isChallengeEnabled(challenges.xxeDosChallenge)) {
    void it('POST file type XML with XXE attack against Windows is rejected without disclosing the file', async () => {
      const file = path.resolve(__dirname, '../files/xxeForWindows.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 410)
      assert.ok(res.text.includes('XML documents must not contain a DTD'))
      assert.ok(!res.text.includes('16-bit app support'))
    })

    void it('POST file type XML with XXE attack against Linux is rejected without disclosing the file', async () => {
      const file = path.resolve(__dirname, '../files/xxeForLinux.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 410)
      assert.ok(res.text.includes('XML documents must not contain a DTD'))
      assert.doesNotMatch(res.text, /root:.*:0:0:/)
    })

    void it('POST UTF-7 encoded XML with XXE attack does not disclose the file', async () => {
      const payload = Buffer.from('<?xml version="1.0" encoding="UTF-7"?>+ADw-+ACE-DOCTYPE foo +AFs-+ADw-+ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe+ADs-+ADw-/foo+AD4-')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'xxeUtf7.xml')
      assert.equal(res.status, 410)
      assert.doesNotMatch(res.text, /root:.*:0:0:/)
    })

    void it('POST malformed XML does not reflect parser errors', async () => {
      const res = await request(app)
        .post('/file-upload')
        .attach('file', Buffer.from('<foo><bar></foo>'), 'malformed.xml')
      assert.equal(res.status, 410)
      assert.ok(res.text.includes('invalid XML document'))
      assert.ok(!res.text.includes('mismatch'))
    })

    void it('POST file type XML with Billion Laughs attack is rejected', async () => {
      const file = path.resolve(__dirname, '../files/xxeBillionLaughs.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 410)
      assert.ok(res.text.includes('XML documents must not contain a DTD'))
    })

    void it('POST file type XML with Quadratic Blowup attack', async () => {
      const file = path.resolve(__dirname, '../files/xxeQuadraticBlowup.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.ok(res.status >= 410)
    })

    void it('POST file type XML with dev/random attack', async () => {
      const file = path.resolve(__dirname, '../files/xxeDevRandom.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.ok(res.status >= 410)
    })

    void it('POST XML with dev/random entity declared only inside a comment is not treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!-- <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]> --><foo>&amp;xxe;</foo>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'commented.xml')
      assert.equal(res.status, 410)
    })

    void it('POST XML with dev/random entity after a quoted comment opener in another entity value is treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY decoy "<!--"><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'quotedComment.xml')
      assert.equal(res.status, 503)
    })

    void it('POST XML with dev/random parameter entity is treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///dev/random"> %xxe;]><foo/>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'parameterEntity.xml')
      assert.equal(res.status, 503)
    })
  }

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
