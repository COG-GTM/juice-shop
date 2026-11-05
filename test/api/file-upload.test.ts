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
let authHeader: { Authorization: string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  authHeader = { Authorization: 'Bearer ' + token }
}, { timeout: 60000 })

void describe('/file-upload', () => {
  void it('POST file without authentication is rejected', async () => {
    const file = path.resolve(__dirname, '../files/zipSlipTemplateOverwrite.zip')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 401)
  })

  void it('POST file valid PDF for client and API', async () => {
    const file = path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .set(authHeader)
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file too large for client validation but valid for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidSizeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .set(authHeader)
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file with illegal type for client validation but valid for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidTypeForClient.exe')
    const res = await request(app)
      .post('/file-upload')
      .set(authHeader)
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file type XML deprecated for API', async () => {
    const file = path.resolve(__dirname, '../files/deprecatedTypeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .set(authHeader)
      .attach('file', file)
    assert.equal(res.status, 410)
    assert.ok(!res.text.includes('Apple Juice'))
  })

  void it('POST large XML file near upload size limit', async () => {
    const file = path.resolve(__dirname, '../files/maxSizeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .set(authHeader)
      .attach('file', file)
    assert.equal(res.status, 410)
  })

  if (utils.isChallengeEnabled(challenges.xxeFileDisclosureChallenge) || utils.isChallengeEnabled(challenges.xxeDosChallenge)) {
    void it('POST file type XML with XXE attack against Windows is rejected without disclosing the file', async () => {
      const file = path.resolve(__dirname, '../files/xxeForWindows.xml')
      const res = await request(app)
        .post('/file-upload')
        .set(authHeader)
        .attach('file', file)
      assert.equal(res.status, 410)
      assert.ok(res.text.includes('XML documents must not contain a DTD'))
      assert.ok(!res.text.includes('16-bit app support'))
    })

    void it('POST file type XML with XXE attack against Linux is rejected without disclosing the file', async () => {
      const file = path.resolve(__dirname, '../files/xxeForLinux.xml')
      const res = await request(app)
        .post('/file-upload')
        .set(authHeader)
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
        .set(authHeader)
        .attach('file', file)
      assert.equal(res.status, 410)
      assert.ok(res.text.includes('XML documents must not contain a DTD'))
    })

    void it('POST file type XML with Quadratic Blowup attack', async () => {
      const file = path.resolve(__dirname, '../files/xxeQuadraticBlowup.xml')
      const res = await request(app)
        .post('/file-upload')
        .set(authHeader)
        .attach('file', file)
      assert.ok(res.status >= 410)
    })

    void it('POST file type XML with dev/random attack', async () => {
      const file = path.resolve(__dirname, '../files/xxeDevRandom.xml')
      const res = await request(app)
        .post('/file-upload')
        .set(authHeader)
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

    void it('POST XML with dev/random entity referenced only inside CDATA is not treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo><![CDATA[&xxe;]]></foo>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'cdata.xml')
      assert.equal(res.status, 410)
    })

    void it('POST XML with dev/random parameter entity referenced after a quoted bracket is treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///dev/random"><!ENTITY bracket "]"> %xxe;]><foo/>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'quotedBracket.xml')
      assert.equal(res.status, 503)
    })

    void it('POST XML with dev/random entity referenced only from an unused internal entity is not treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random"><!ENTITY unused "&xxe;">]><foo/>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'unusedInternalEntity.xml')
      assert.equal(res.status, 410)
    })

    void it('POST XML with dev/random entity referenced through a used internal entity is treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random"><!ENTITY wrap "&xxe;">]><foo>&wrap;</foo>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'nestedEntity.xml')
      assert.equal(res.status, 503)
    })

    void it('POST XML with dev/random entity after a processing instruction containing a comment opener is treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><?note <!-- ?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'processingInstruction.xml')
      assert.equal(res.status, 503)
    })

    void it('POST XML with dev/random parameter entity referenced only in element text is not treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///dev/random">]><foo>%xxe;</foo>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'parameterEntityText.xml')
      assert.equal(res.status, 410)
    })

    void it('POST XML with dev/random entity referenced only in an attribute value is not treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo attr="&xxe;"/>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'attributeReference.xml')
      assert.equal(res.status, 410)
    })

    void it('POST XML with dev/random entity declared through an internal parameter entity is treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % decl \'<!ENTITY xxe SYSTEM "file:///dev/random">\'> %decl;]><foo>&xxe;</foo>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'parameterEntityDeclaration.xml')
      assert.equal(res.status, 503)
    })

    void it('POST malformed XML with dev/random entity is not treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</bar>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'malformedEntity.xml')
      assert.equal(res.status, 410)
    })

    void it('POST XML with dev/random entity in an invalid DTD is not treated as an attack', async () => {
      const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random"> nonsense ]><foo>&xxe;</foo>')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', payload, 'invalidDtd.xml')
      assert.equal(res.status, 410)
    })
  }

  if (utils.isChallengeEnabled(challenges.yamlBombChallenge)) {
    void it('POST file type YAML with Billion Laughs-style attack', async () => {
      const file = path.resolve(__dirname, '../files/yamlBomb.yml')
      const res = await request(app)
        .post('/file-upload')
        .set(authHeader)
        .attach('file', file)
      assert.ok(res.status >= 410)
    })
  }

  void it('POST file too large for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidSizeForServer.pdf')
    const res = await request(app)
      .post('/file-upload')
      .set(authHeader)
      .attach('file', file)
    assert.equal(res.status, 500)
  })

  void it('POST zip file with directory traversal payload', async () => {
    const file = path.resolve(__dirname, '../files/arbitraryFileWrite.zip')
    const res = await request(app)
      .post('/file-upload')
      .set(authHeader)
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  if (utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
    void it('POST zip file with directory traversal payload does not overwrite files outside uploads/complaints', async () => {
      const legalFile = path.resolve('ftp/legal.md')
      const original = fs.readFileSync(legalFile, 'utf8')
      const sentinel = `zip slip sentinel ${Date.now()}`
      fs.writeFileSync(legalFile, sentinel)
      try {
        challenges.fileWriteChallenge.solved = false
        const file = path.resolve(__dirname, '../files/arbitraryFileWrite.zip')
        const res = await request(app)
          .post('/file-upload')
          .set(authHeader)
          .attach('file', file)
        assert.equal(res.status, 204)
        for (let i = 0; i < 50 && !challenges.fileWriteChallenge.solved; i++) {
          await new Promise(resolve => setTimeout(resolve, 100))
        }
        assert.equal(challenges.fileWriteChallenge.solved, true)
        assert.equal(fs.readFileSync(legalFile, 'utf8'), sentinel)
      } finally {
        fs.writeFileSync(legalFile, original)
      }
    })

    void it('POST zip file with traversal entries does not overwrite server-side Pug templates', async () => {
      const templates = ['views/promotionVideo.pug', 'views/userProfile.pug'].map(file => path.resolve(file))
      const originals = templates.map(file => fs.readFileSync(file, 'utf8'))
      const file = path.resolve(__dirname, '../files/zipSlipTemplateOverwrite.zip')
      const res = await request(app)
        .post('/file-upload')
        .set(authHeader)
        .attach('file', file)
      assert.equal(res.status, 204)
      await new Promise(resolve => setTimeout(resolve, 500))
      templates.forEach((template, i) => { assert.equal(fs.readFileSync(template, 'utf8'), originals[i]) })
    })

    void it('POST zip file with a valid entry persists it in uploads/complaints', async () => {
      const entry = path.resolve('uploads/complaints/valid-complaint-evidence.txt')
      fs.rmSync(entry, { force: true })
      try {
        const file = path.resolve(__dirname, '../files/validComplaint.zip')
        const res = await request(app)
          .post('/file-upload')
          .set(authHeader)
          .attach('file', file)
        assert.equal(res.status, 204)
        assert.equal(fs.readFileSync(entry, 'utf8'), 'Valid complaint evidence\n')
      } finally {
        fs.rmSync(entry, { force: true })
      }
    })

    void it('POST zip file exceeding the entry limit does not persist any of its entries', async () => {
      const entries = Array.from({ length: 101 }, (_, i) => path.resolve('uploads/complaints', `entry-limit-${i}.txt`))
      entries.forEach(entry => { fs.rmSync(entry, { force: true }) })
      const file = path.resolve(__dirname, '../files/tooManyComplaintEntries.zip')
      const res = await request(app)
        .post('/file-upload')
        .set(authHeader)
        .attach('file', file)
      assert.equal(res.status, 413)
      assert.match(res.body.error, /exceeds the limit of 100 entries/)
      await new Promise(resolve => setTimeout(resolve, 500))
      assert.deepEqual(entries.filter(entry => fs.existsSync(entry)), [])
    })

    void it('POST zip file with an entry targeting an existing directory persists none of its entries', async () => {
      const directory = path.resolve('uploads/complaints/rename-conflict-dir')
      const sibling = path.resolve('uploads/complaints/rename-conflict-ok.txt')
      fs.rmSync(sibling, { force: true })
      fs.mkdirSync(directory, { recursive: true })
      try {
        const file = path.resolve(__dirname, '../files/complaintTargetIsDirectory.zip')
        const res = await request(app)
          .post('/file-upload')
          .set(authHeader)
          .attach('file', file)
        assert.equal(res.status, 500)
        assert.equal(fs.existsSync(sibling), false)
        assert.equal(fs.statSync(directory).isDirectory(), true)
      } finally {
        fs.rmSync(directory, { recursive: true, force: true })
      }
    })

    void it('POST corrupt zip file is rejected', async () => {
      const file = path.resolve(__dirname, '../files/corruptComplaint.zip')
      const res = await request(app)
        .post('/file-upload')
        .set(authHeader)
        .attach('file', file)
      assert.equal(res.status, 400)
      assert.equal(res.body.error, 'Invalid ZIP archive')
    })

    void it('POST zip file with a malformed record after a valid entry is rejected', async () => {
      const file = path.resolve(__dirname, '../files/truncatedComplaint.zip')
      const res = await request(app)
        .post('/file-upload')
        .set(authHeader)
        .attach('file', file)
      assert.equal(res.status, 400)
      assert.equal(res.body.error, 'Invalid ZIP archive')
      assert.equal(fs.existsSync(path.resolve('uploads/complaints/evidence.pdf')), false)
    })
  }

  void it('POST zip file with password protection', async () => {
    const file = path.resolve(__dirname, '../files/passwordProtected.zip')
    const res = await request(app)
      .post('/file-upload')
      .set(authHeader)
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST valid file with tampered content length', { skip: 'Fails on CI/CD pipeline' }, async () => {
    const file = path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .set(authHeader)
      .set('Content-Length', '42')
      .attach('file', file)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Unexpected end of form'))
  })
})
