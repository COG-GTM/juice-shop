/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import fs from 'node:fs'
import path from 'node:path'
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

  void it('POST file with illegal type is rejected by API', async () => {
    const file = path.resolve(__dirname, '../files/invalidTypeForClient.exe')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 415)
  })

  void it('POST file with PDF extension but non-PDF content is rejected by API', async () => {
    const res = await request(app)
      .post('/file-upload')
      .attach('file', Buffer.from('MZ not really a PDF'), 'disguised.pdf')
    assert.equal(res.status, 415)
  })

  void it('POST file type XML deprecated for API', async () => {
    const file = path.resolve(__dirname, '../files/deprecatedTypeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
  })

  for (const xmlFile of ['maxSizeForServer.xml', 'xxeForWindows.xml', 'xxeForLinux.xml', 'xxeBillionLaughs.xml', 'xxeQuadraticBlowup.xml', 'xxeDevRandom.xml']) {
    void it(`POST ${xmlFile} is rejected without being parsed`, async () => {
      const file = path.resolve(__dirname, '../files/' + xmlFile)
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 410)
      assert.ok(!res.text.includes('root:x:0:0'))
      assert.ok(!res.text.includes('[fonts]'))
    })
  }

  void it('POST file type YAML with Billion Laughs-style attack is rejected without being parsed', async () => {
    const file = path.resolve(__dirname, '../files/yamlBomb.yml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
  })

  void it('POST file too large for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidSizeForServer.pdf')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 500)
  })

  void it('POST zip file with directory traversal payload does not write outside upload directory', async () => {
    const legalFile = path.resolve('ftp/legal.md')
    const legalContent = fs.readFileSync(legalFile, 'utf8')
    const file = path.resolve(__dirname, '../files/arbitraryFileWrite.zip')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
    await new Promise(resolve => setTimeout(resolve, 500))
    assert.equal(fs.readFileSync(legalFile, 'utf8'), legalContent)
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
