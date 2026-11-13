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

async function uploadSolvesFileDisclosure (upload: () => Promise<request.Response>) {
  const challenge = challenges.xxeFileDisclosureChallenge
  const wasSolved = challenge.solved
  challenge.solved = false
  try {
    const res = await upload()
    if (utils.isChallengeEnabled(challenge)) {
      assert.equal(challenge.solved, true, 'expected xxeFileDisclosureChallenge to be solved')
    }
    return res
  } finally {
    challenge.solved = wasSolved || challenge.solved
  }
}

function itWhenXxeEnabled (name: string, fn: () => Promise<void>) {
  void it(name, async (t) => {
    if (!utils.isChallengeEnabled(challenges.xxeFileDisclosureChallenge) && !utils.isChallengeEnabled(challenges.xxeDosChallenge)) {
      t.skip('XXE challenges are disabled in this environment')
      return
    }
    await fn()
  })
}

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

  void it('POST XML with XXE attack never discloses the file regardless of enabled challenges', async () => {
    const file = path.resolve(__dirname, '../files/xxeForLinux.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assert.doesNotMatch(res.text, /root:.*:0:0:/)
  })

  void itWhenXxeEnabled('POST file type XML with XXE attack against Windows is rejected without disclosing the file', async () => {
    const file = path.resolve(__dirname, '../files/xxeForWindows.xml')
    const res = await uploadSolvesFileDisclosure(async () => await request(app)
      .post('/file-upload')
      .attach('file', file))
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('XML documents must not contain a DTD'))
    assert.ok(!res.text.includes('16-bit app support'))
  })

  void itWhenXxeEnabled('POST file type XML with XXE attack against Linux is rejected without disclosing the file', async () => {
    const file = path.resolve(__dirname, '../files/xxeForLinux.xml')
    const res = await uploadSolvesFileDisclosure(async () => await request(app)
      .post('/file-upload')
      .attach('file', file))
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('XML documents must not contain a DTD'))
    assert.doesNotMatch(res.text, /root:.*:0:0:/)
  })

  void itWhenXxeEnabled('POST UTF-7 encoded XML with XXE attack does not disclose the file', async () => {
    const payload = Buffer.from('<?xml version="1.0" encoding="UTF-7"?>+ADw-+ACE-DOCTYPE foo +AFs-+ADw-+ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe+ADs-+ADw-/foo+AD4-')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'xxeUtf7.xml')
    assert.equal(res.status, 410)
    assert.doesNotMatch(res.text, /root:.*:0:0:/)
  })

  void itWhenXxeEnabled('POST malformed XML does not reflect parser errors', async () => {
    const res = await request(app)
      .post('/file-upload')
      .attach('file', Buffer.from('<foo><bar></foo>'), 'malformed.xml')
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('invalid XML document'))
    assert.ok(!res.text.includes('mismatch'))
  })

  void itWhenXxeEnabled('POST file type XML with Billion Laughs attack is rejected', async () => {
    const file = path.resolve(__dirname, '../files/xxeBillionLaughs.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
    assert.ok(res.text.includes('XML documents must not contain a DTD'))
  })

  void itWhenXxeEnabled('POST file type XML with Quadratic Blowup attack', async () => {
    const file = path.resolve(__dirname, '../files/xxeQuadraticBlowup.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.ok(res.status >= 410)
  })

  void itWhenXxeEnabled('POST file type XML with dev/random attack', async () => {
    const file = path.resolve(__dirname, '../files/xxeDevRandom.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.ok(res.status >= 410)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity declared only inside a comment is not treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!-- <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]> --><foo>&amp;xxe;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'commented.xml')
    assert.equal(res.status, 410)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity after a quoted comment opener in another entity value is treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY decoy "<!--"><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'quotedComment.xml')
    assert.equal(res.status, 503)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity and DTD-like text in a trailing comment is treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;<!-- <!DOCTYPE example> --></foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'trailing-comment.xml')
    assert.equal(res.status, 503)
  })

  void itWhenXxeEnabled('POST XML with dev/random parameter entity is treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///dev/random"> %xxe;]><foo/>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'parameterEntity.xml')
    assert.equal(res.status, 503)
  })

  void itWhenXxeEnabled('POST XML with a deep entity chain referenced from an attribute is rejected without a server error', async () => {
    const depth = 7500
    const declarations = Array.from({ length: depth }, (_, i) => `<!ENTITY e${i} "&e${i + 1};">`).join('')
    const payload = Buffer.from(`<?xml version="1.0"?><!DOCTYPE f [${declarations}<!ENTITY e${depth} SYSTEM "file:///etc/passwd">]><f a="&e0;"/>`)
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'deepEntityChain.xml')
    assert.equal(res.status, 410)
    assert.ok(!res.text.includes('root:'))
  })

  void itWhenXxeEnabled('POST XML with overlapping entity chains referenced from an attribute is scanned in linear time', async () => {
    const depth = 5500
    const declarations = Array.from({ length: depth }, (_, i) => `<!ENTITY e${i} "&e${i + 1};">`).join('')
    const references = Array.from({ length: depth }, (_, i) => `&e${i};`).join('')
    const payload = Buffer.from(`<?xml version="1.0"?><!DOCTYPE f [${declarations}<!ENTITY e${depth} "x">]><f a="${references}"/>`)
    const start = Date.now()
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'overlappingEntityChains.xml')
    assert.equal(res.status, 410)
    assert.ok(Date.now() - start < 3000, `scan took ${Date.now() - start}ms`)
  })

  void itWhenXxeEnabled('POST XML with passwd entity referenced through a character reference in an internal entity solves the challenge without disclosing the file', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"><!ENTITY wrap "&#38;xxe;">]><foo>&wrap;</foo>')
    const res = await uploadSolvesFileDisclosure(async () => await request(app)
      .post('/file-upload')
      .attach('file', payload, 'characterReference.xml'))
    assert.equal(res.status, 410)
    assert.doesNotMatch(res.text, /root:.*:0:0:/)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity referenced through a hex character reference in an internal entity is treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random"><!ENTITY wrap "&#x26;xxe;">]><foo>&wrap;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'hexCharacterReference.xml')
    assert.equal(res.status, 503)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity referenced only inside CDATA is not treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo><![CDATA[&xxe;]]></foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'cdata.xml')
    assert.equal(res.status, 410)
  })

  void itWhenXxeEnabled('POST XML with dev/random parameter entity referenced after a quoted bracket is treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///dev/random"><!ENTITY bracket "]"> %xxe;]><foo/>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'quotedBracket.xml')
    assert.equal(res.status, 503)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity referenced only from an unused internal entity is not treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random"><!ENTITY unused "&xxe;">]><foo/>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'unusedInternalEntity.xml')
    assert.equal(res.status, 410)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity referenced through a used internal entity is treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random"><!ENTITY wrap "&xxe;">]><foo>&wrap;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'nestedEntity.xml')
    assert.equal(res.status, 503)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity after a processing instruction containing a comment opener is treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><?note <!-- ?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'processingInstruction.xml')
    assert.equal(res.status, 503)
  })

  void itWhenXxeEnabled('POST XML with dev/random parameter entity referenced only in element text is not treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///dev/random">]><foo>%xxe;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'parameterEntityText.xml')
    assert.equal(res.status, 410)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity referenced only in an attribute value is not treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo attr="&xxe;"/>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'attributeReference.xml')
    assert.equal(res.status, 410)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity referenced in both an attribute value and element text is not treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo attr="&xxe;">&xxe;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'attributeAndTextReference.xml')
    assert.equal(res.status, 410)
  })

  void itWhenXxeEnabled('POST XML with entity declarations followed by many unterminated tags is rejected quickly', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;' + '<"'.repeat(90000))
    const start = Date.now()
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'unterminatedTags.xml')
    assert.equal(res.status, 410)
    assert.ok(Date.now() - start < 5000)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity declared through an internal parameter entity is treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % decl \'<!ENTITY xxe SYSTEM "file:///dev/random">\'> %decl;]><foo>&xxe;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'parameterEntityDeclaration.xml')
    assert.equal(res.status, 503)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity behind a non-local file URI authority is not treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://dev/random">]><foo>&xxe;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'remoteAuthority.xml')
    assert.equal(res.status, 410)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity behind a localhost authority and redundant path segments is treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://localhost/dev/../dev/./random">]><foo>&xxe;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'normalizedDevRandom.xml')
    assert.equal(res.status, 503)
  })

  void itWhenXxeEnabled('POST XML with non-normalized /etc/passwd path solves the challenge without disclosing the file', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/../etc/passwd">]><foo>&xxe;</foo>')
    const res = await uploadSolvesFileDisclosure(async () => await request(app)
      .post('/file-upload')
      .attach('file', payload, 'normalizedPasswd.xml'))
    assert.equal(res.status, 410)
    assert.doesNotMatch(res.text, /root:.*:0:0:/)
  })

  void itWhenXxeEnabled('POST malformed XML with dev/random entity is not treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</bar>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'malformedEntity.xml')
    assert.equal(res.status, 410)
  })

  void itWhenXxeEnabled('POST XML with dev/random entity in an invalid DTD is not treated as an attack', async () => {
    const payload = Buffer.from('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random"> nonsense ]><foo>&xxe;</foo>')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', payload, 'invalidDtd.xml')
    assert.equal(res.status, 410)
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
