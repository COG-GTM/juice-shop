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

  void it('POST large XML file near upload size limit', async () => {
    const file = path.resolve(__dirname, '../files/maxSizeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
  })

  if (utils.isChallengeEnabled(challenges.xxeFileDisclosureChallenge) || utils.isChallengeEnabled(challenges.xxeDosChallenge)) {
    void it('POST file type XML with XXE attack against Windows', async () => {
      const file = path.resolve(__dirname, '../files/xxeForWindows.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 410)
    })

    void it('POST file type XML with XXE attack against Linux', async () => {
      const file = path.resolve(__dirname, '../files/xxeForLinux.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 410)
    })

    void it('POST file type XML with Billion Laughs attack is caught by parser', async () => {
      const file = path.resolve(__dirname, '../files/xxeBillionLaughs.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 410)
      assert.ok(res.text.includes('Detected an entity reference loop'))
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

  void it('POST zip file with directory traversal entry does not write outside uploads/complaints', async () => {
    const marker = path.resolve('zipSlipRegressionMarker.txt')
    const benign = path.resolve('uploads/complaints/zipSlipRegressionBenign.txt')
    fs.rmSync(marker, { force: true })
    fs.rmSync(benign, { force: true })
    try {
      const file = path.resolve(__dirname, '../files/zipSlipTraversal.zip')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 204)

      for (let i = 0; i < 50 && !fs.existsSync(benign); i++) {
        await new Promise(resolve => setTimeout(resolve, 100))
      }
      assert.ok(fs.existsSync(benign), 'benign entry should be extracted into uploads/complaints')
      assert.equal(fs.existsSync(marker), false, 'traversal entry must not be written outside uploads/complaints')
    } finally {
      fs.rmSync(marker, { force: true })
      fs.rmSync(benign, { force: true })
    }
  })

  void it('POST zip file entry is not written through a symlink inside uploads/complaints', async () => {
    const target = path.resolve('zipSlipSymlinkTarget.txt')
    const link = path.resolve('uploads/complaints/zipSlipSymlinkEntry.txt')
    fs.rmSync(link, { force: true })
    fs.writeFileSync(target, 'untouched')
    fs.symlinkSync(target, link)
    try {
      const file = path.resolve(__dirname, '../files/zipSlipSymlink.zip')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 204)

      await new Promise(resolve => setTimeout(resolve, 2000))
      assert.equal(fs.readFileSync(target, 'utf8'), 'untouched', 'symlinked entry must not be followed out of uploads/complaints')
    } finally {
      fs.rmSync(link, { force: true })
      fs.rmSync(target, { force: true })
    }
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
