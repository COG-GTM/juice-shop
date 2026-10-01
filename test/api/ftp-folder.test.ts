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

function responseText (res: request.Response): string {
  return res.text ?? (Buffer.isBuffer(res.body) ? res.body.toString('utf-8') : '')
}

void describe('/ftp', () => {
  void it('GET does not serve a directory listing', async () => {
    const res = await request(app)
      .get('/ftp')
    assert.ok(!res.text.includes('listing directory'))
  })

  void it('GET a non-existing order PDF in /ftp will return a 404 error', async () => {
    const res = await request(app)
      .get('/ftp/order_0000-0000000000000000.pdf')
    assert.equal(res.status, 404)
  })

  for (const file of [
    'doesnotexist.md',
    'doesnotexist.pdf',
    'doesnotexist.exe',
    'eastere.gg',
    'coupons_2013.md.bak',
    'package.json.bak',
    'suspicious_errors.yml',
    'acquisitions.md',
    'announcement_encrypted.md',
    'incident-support.kdbx',
    'encrypt.pyc'
  ]) {
    void it(`GET /ftp/${file} is refused with a 403 error`, async () => {
      const res = await request(app)
        .get('/ftp/' + file)
      assert.equal(res.status, 403)
    })
  }

  for (const file of [
    'eastere.gg%2500.pdf',
    'eastere.gg%2500.md',
    'suspicious_errors.yml%2500.md',
    'coupons_2013.md.bak%2500.md',
    'package.json.bak%2500.md',
    'encrypt.pyc%2500.md',
    'eastere.gg%00.md',
    'legal.md%2500'
  ]) {
    void it(`GET /ftp/${file} via Poison Null Byte attack is refused with a 403 error`, async () => {
      const res = await request(app)
        .get('/ftp/' + file)
        .buffer(true)
      assert.equal(res.status, 403)
      assert.ok(!responseText(res).includes('Congratulations, you found the easter egg!'))
    })
  }

  void it('GET a restricted file directly from file system path on server by tricking route definitions fails with 403 error', async () => {
    const res = await request(app)
      .get('/ftp///eastere.gg')
    assert.equal(res.status, 403)
  })

  void it('GET a restricted file directly from file system path on server by appending URL parameter fails with 403 error', async () => {
    const res = await request(app)
      .get('/ftp/eastere.gg?.md')
    assert.equal(res.status, 403)
  })

  void it('GET a file whose name contains a "/" fails with a 403 error', async () => {
    const res = await request(app)
      .get('/ftp/%2fetc%2fos-release%2500.md')
    assert.equal(res.status, 403)
  })

  void it('GET the public legal information file', async () => {
    const res = await request(app)
      .get('/ftp/legal.md')
    assert.equal(res.status, 200)
    assert.ok(res.text.includes('# Legal Information'))
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
