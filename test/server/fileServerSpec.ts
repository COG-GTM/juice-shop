/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

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

  it('should raise error for disallowed file type hidden behind a Poison Null Byte', () => {
    req.params.file = 'package.json.bak%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(403)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should serve the allowlisted file left after cutting off a Poison Null Byte', () => {
    req.params.file = 'legal.md%00.pdf'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]legal\.md$/))
  })

  it('should solve "easterEggLevelOneChallenge" when attempting a Poison Null Byte attack on eastere.gg', () => {
    challenges.easterEggLevelOneChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'eastere.gg%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(challenges.easterEggLevelOneChallenge.solved).to.equal(true)
  })

  it('should solve "forgottenDevBackupChallenge" when attempting a Poison Null Byte attack on package.json.bak', () => {
    challenges.forgottenDevBackupChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'package.json.bak%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(challenges.forgottenDevBackupChallenge.solved).to.equal(true)
  })

  it('should solve "forgottenBackupChallenge" when attempting a Poison Null Byte attack on coupons_2013.md.bak', () => {
    challenges.forgottenBackupChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'coupons_2013.md.bak%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(challenges.forgottenBackupChallenge.solved).to.equal(true)
  })

  it('should solve "misplacedSignatureFileChallenge" when attempting a Poison Null Byte attack on suspicious_errors.yml', () => {
    challenges.misplacedSignatureFileChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'suspicious_errors.yml%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(challenges.misplacedSignatureFileChallenge.solved).to.equal(true)
  })

  it('should not solve "easterEggLevelOneChallenge" for a Poison Null Byte without an allowlisted suffix', () => {
    challenges.easterEggLevelOneChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'eastere.gg%00'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(challenges.easterEggLevelOneChallenge.solved).to.equal(false)
  })

  it('should solve "nullByteChallenge" for a Poison Null Byte on an allowlisted file once a backup challenge is solved', () => {
    challenges.forgottenDevBackupChallenge = { solved: true, save } as unknown as Challenge
    challenges.nullByteChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'legal.md%00.pdf'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]legal\.md$/))
    expect(challenges.nullByteChallenge.solved).to.equal(true)
  })
})
