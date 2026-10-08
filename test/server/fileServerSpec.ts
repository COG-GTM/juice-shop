/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { servePublicFiles } from '../../routes/fileServer'
import * as security from '../../lib/insecurity'
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
    req = { params: {}, query: {}, headers: { authorization: 'Bearer ' + security.authorize({ data: { email: 'admin@juice-sh.op', role: 'admin' } }) } }
    next = sinon.spy()
    save = () => ({
      then () { }
    })
  })

  it('should serve the public legal.md to anonymous users', () => {
    req.headers = {}
    req.params.file = 'legal.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]legal\.md/))
  })

  it('should serve order confirmation PDFs to anonymous users', () => {
    req.headers = {}
    req.params.file = 'order_5267-f9cd5882f54c75a3.pdf'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]order_5267-f9cd5882f54c75a3\.pdf/))
  })

  it('should deny confidential files to anonymous users with 401', () => {
    req.headers = {}
    req.params.file = 'acquisitions.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(401)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should deny confidential files to non-admin users with 403', () => {
    req.headers = { authorization: 'Bearer ' + security.authorize({ data: { email: 'jim@juice-sh.op', role: 'customer' } }) }
    req.params.file = 'acquisitions.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(403)
  })

  it('should deny confidential files when requested with a poison null byte by anonymous users', () => {
    req.headers = {}
    req.params.file = 'package.json.bak%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(401)
  })

  it('should serve PDF files from folder /ftp', () => {
    req.params.file = 'test.pdf'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]test\.pdf/))
  })

  it('should serve Markdown files from folder /ftp', () => {
    req.params.file = 'test.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]test\.md/))
  })

  it('should serve incident-support.kdbx files from folder /ftp', () => {
    req.params.file = 'incident-support.kdbx'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]incident-support\.kdbx/))
  })

  it('should raise error for slashes in filename', () => {
    req.params.file = '../../../../nice.try'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for disallowed file type', () => {
    req.params.file = 'nice.try'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should solve "directoryListingChallenge" when requesting acquisitions.md', () => {
    challenges.directoryListingChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'acquisitions.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]acquisitions\.md/))
    expect(challenges.directoryListingChallenge.solved).to.equal(true)
  })

  it('should solve "easterEggLevelOneChallenge" when requesting eastere.gg with Poison Null Byte attack', () => {
    challenges.easterEggLevelOneChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'eastere.gg%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]eastere\.gg/))
    expect(challenges.easterEggLevelOneChallenge.solved).to.equal(true)
  })

  it('should solve "forgottenDevBackupChallenge" when requesting package.json.bak with Poison Null Byte attack', () => {
    challenges.forgottenDevBackupChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'package.json.bak%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]package\.json\.bak/))
    expect(challenges.forgottenDevBackupChallenge.solved).to.equal(true)
  })

  it('should solve "forgottenBackupChallenge" when requesting coupons_2013.md.bak with Poison Null Byte attack', () => {
    challenges.forgottenBackupChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'coupons_2013.md.bak%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]coupons_2013\.md\.bak/))
    expect(challenges.forgottenBackupChallenge.solved).to.equal(true)
  })

  it('should solve "misplacedSignatureFileChallenge" when requesting suspicious_errors.yml with Poison Null Byte attack', () => {
    challenges.misplacedSignatureFileChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'suspicious_errors.yml%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]suspicious_errors\.yml/))
    expect(challenges.misplacedSignatureFileChallenge.solved).to.equal(true)
  })
})
