/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { servePublicFiles } from '../../routes/fileServer'
import { type Challenge } from 'data/types'
const expect = chai.expect
chai.use(sinonChai)

describe('fileServer', () => {
  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    req = { params: {}, query: {} }
    next = sinon.spy()
    save = () => ({
      then () { }
    })
  })

  it('should serve the public legal.md from folder /ftp', async () => {
    const legalFile = path.resolve('ftp/legal.md')
    const createdForTest = !fs.existsSync(legalFile)
    if (createdForTest) fs.copyFileSync(path.resolve('data/static/legal.md'), legalFile)
    req.params.file = 'legal.md'

    try {
      await servePublicFiles()(req, res, next)
    } finally {
      if (createdForTest) fs.unlinkSync(legalFile)
    }

    expect(res.sendFile).to.have.been.calledWith('legal.md', sinon.match({ root: sinon.match(/ftp$/) }))
  })

  it('should serve order confirmation PDFs from folder /ftp', async () => {
    const orderFile = 'order_5267-f0a1b2c3d4e5f6a7.pdf'
    fs.writeFileSync(path.resolve('ftp', orderFile), '%PDF-1.3')
    req.params.file = orderFile

    try {
      await servePublicFiles()(req, res, next)
    } finally {
      fs.unlinkSync(path.resolve('ftp', orderFile))
    }

    expect(res.sendFile).to.have.been.calledWith(orderFile, sinon.match({ root: sinon.match(/ftp$/) }))
  })

  for (const file of ['acquisitions.md', 'announcement_encrypted.md']) {
    it(`should respond 404 for internal file ${file} although it exists in /ftp`, async () => {
      challenges.directoryListingChallenge = { solved: false, save } as unknown as Challenge
      req.params.file = file

      await servePublicFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(404)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
      expect(challenges.directoryListingChallenge.solved).to.equal(false)
    })
  }

  it('should respond 404 for allowlisted file types that do not exist in /ftp', async () => {
    req.params.file = 'order_0000-0000000000000000.pdf'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(404)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for incident-support.kdbx', async () => {
    req.params.file = 'incident-support.kdbx'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(403)
  })

  it('should raise error for slashes in filename', async () => {
    req.params.file = '../../../../nice.try'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for backslashes in filename', async () => {
    req.params.file = '..\\package.json.md'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(403)
  })

  it('should raise error for disallowed file type', async () => {
    req.params.file = 'nice.try'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  for (const file of ['eastere.gg%00.md', 'package.json.bak%00.md', 'coupons_2013.md.bak%00.pdf', 'coupons_2013.md.bak%2500.md', 'suspicious_errors.yml%00.md', 'encrypt.pyc%00.md', 'incident-support.kdbx%00.md', 'package.json.bak\0.md']) {
    it(`should reject Poison Null Byte attack ${JSON.stringify(file)} without serving the truncated file`, async () => {
      challenges.easterEggLevelOneChallenge = { solved: false, save } as unknown as Challenge
      challenges.forgottenDevBackupChallenge = { solved: false, save } as unknown as Challenge
      challenges.forgottenBackupChallenge = { solved: false, save } as unknown as Challenge
      challenges.misplacedSignatureFileChallenge = { solved: false, save } as unknown as Challenge
      challenges.nullByteChallenge = { solved: false, save } as unknown as Challenge
      req.params.file = file

      await servePublicFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(403)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
      expect(challenges.easterEggLevelOneChallenge.solved).to.equal(false)
      expect(challenges.forgottenDevBackupChallenge.solved).to.equal(false)
      expect(challenges.forgottenBackupChallenge.solved).to.equal(false)
      expect(challenges.misplacedSignatureFileChallenge.solved).to.equal(false)
      expect(challenges.nullByteChallenge.solved).to.equal(false)
    })
  }
})
