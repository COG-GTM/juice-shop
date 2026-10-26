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

void describe('/ftp', () => {
  void it('GET does not serve a directory listing', async () => {
    const res = await request(app)
      .get('/ftp')
    assert.equal(res.status, 404)
    assert.ok(!res.text.includes('listing directory /ftp'))
  })

  void it('GET the public legal information file in /ftp', async () => {
    const res = await request(app)
      .get('/ftp/legal.md')
    assert.equal(res.status, 200)
    assert.ok(res.text.includes('# Legal Information'))
  })

  for (const file of ['acquisitions.md', 'announcement_encrypted.md', 'incident-support.kdbx', 'eastere.gg', 'coupons_2013.md.bak', 'package.json.bak', 'suspicious_errors.yml', 'encrypt.pyc', 'doesnotexist.md', 'doesnotexist.pdf', 'order_0000-0000000000000000.pdf']) {
    void it(`GET non-public file /ftp/${file} returns a 404 error`, async () => {
      const res = await request(app)
        .get(`/ftp/${file}`)
      assert.equal(res.status, 404)
    })
  }

  for (const file of ['eastere.gg%2500.md', 'eastere.gg%2500.pdf', 'suspicious_errors.yml%2500.md', 'coupons_2013.md.bak%2500.md', 'package.json.bak%2500.pdf', 'encrypt.pyc%2500.md', '%2fetc%2fos-release%2500.md']) {
    void it(`GET /ftp/${file} via Poison Null Byte attack returns a 404 error`, async () => {
      const res = await request(app)
        .get(`/ftp/${file}`)
        .buffer(true)
      assert.equal(res.status, 404)
    })
  }

  void it('GET a non-public file by tricking route definitions returns a 404 error', async () => {
    const res = await request(app)
      .get('/ftp///eastere.gg')
    assert.equal(res.status, 404)
  })

  void it('GET a non-public file by appending URL parameter returns a 404 error', async () => {
    const res = await request(app)
      .get('/ftp/eastere.gg?.md')
    assert.equal(res.status, 404)
  })

  void it('GET file /ftp/quarantine/juicy_malware_linux_amd_64.url', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/juicy_malware_linux_amd_64.url')
    assert.equal(res.status, 200)
  })

  void it('GET file /ftp/quarantine/juicy_malware_linux_arm_64.url', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/juicy_malware_linux_arm_64.url')
    assert.equal(res.status, 200)
  })

  void it('GET existing file /ftp/quarantine/juicy_malware_macos_64.url', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/juicy_malware_macos_64.url')
    assert.equal(res.status, 200)
  })

  void it('GET existing file /ftp/quarantine/juicy_malware_windows_64.exe.url', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/juicy_malware_windows_64.exe.url')
    assert.equal(res.status, 200)
  })
})
