/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinonChai from 'sinon-chai'
import sinon from 'sinon'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType } from '../../routes/fileUpload'

const expect = chai.expect
chai.use(sinonChai)

describe('fileUpload', () => {
  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    req = { file: { originalname: '', buffer: Buffer.from('%PDF-1.4') } }
    res = { status: sinon.stub().returnsThis(), json: sinon.stub().returnsThis() }
    next = sinon.spy()
    save = () => ({
      then () { }
    })
  })

  describe('should not solve "uploadSizeChallenge" when file size is', () => {
    const sizes = [0, 1, 100, 1000, 10000, 99999, 100000]
    sizes.forEach(size => {
      it(`${size} bytes`, () => {
        challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
        req.file.size = size

        checkUploadSize(req, res, next)

        expect(challenges.uploadSizeChallenge.solved).to.equal(false)
        expect(next.calledOnce).to.equal(true)
        expect(res.status.called).to.equal(false)
      })
    })
  })

  it('should solve "uploadSizeChallenge" and reject the upload when file size exceeds 100000 bytes', () => {
    challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
    req.file.size = 100001

    checkUploadSize(req, res, next)

    expect(challenges.uploadSizeChallenge.solved).to.equal(true)
    expect(res.status).to.have.been.calledWith(400)
    expect(next.called).to.equal(false)
  })

  it('should solve "uploadTypeChallenge" and reject the upload when file type is not allowed', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.exe'

    checkFileType(req, res, next)

    expect(challenges.uploadTypeChallenge.solved).to.equal(true)
    expect(res.status).to.have.been.calledWith(400)
    expect(next.called).to.equal(false)
  })

  it('should reject a file without extension', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack'

    checkFileType(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
    expect(next.called).to.equal(false)
  })

  it('should not solve "uploadTypeChallenge" when file type is PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.pdf'

    checkFileType(req, res, next)

    expect(challenges.uploadTypeChallenge.solved).to.equal(false)
    expect(next.calledOnce).to.equal(true)
  })

  const validContent: Record<string, Buffer> = {
    'complaint.pdf': Buffer.from('%PDF-1.7\n%%EOF\n'),
    'complaint.PDF': Buffer.from('%PDF-1.7\n%%EOF\n'),
    'complaint.zip': Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x0a, 0x00]),
    'empty.zip': Buffer.from([0x50, 0x4b, 0x05, 0x06, 0x00, 0x00]),
    'complaint.xml': Buffer.from('<?xml version="1.0"?><complaint/>'),
    'bom.xml': Buffer.from('\uFEFF\n  <complaint/>'),
    'complaint.yml': Buffer.from('complaint: true\n'),
    'complaint.yaml': Buffer.from('complaint: true\n')
  }
  Object.entries(validContent).forEach(([originalname, buffer]) => {
    it(`should accept ${originalname} with matching content`, () => {
      req.file = { originalname, buffer }

      checkFileType(req, res, next)

      expect(next.calledOnce).to.equal(true)
      expect(res.status.called).to.equal(false)
    })
  })

  const mismatchedContent: Record<string, Buffer> = {
    'renamed.pdf': Buffer.from([0x4d, 0x5a, 0x90, 0x00]),
    'zeros.pdf': Buffer.alloc(21),
    'renamed.zip': Buffer.from('%PDF-1.7\n'),
    'binary.xml': Buffer.from([0x3c, 0x00, 0x61, 0x3e]),
    'plain.xml': Buffer.from('not markup'),
    'binary.yml': Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00]),
    'latin1.yaml': Buffer.from([0x61, 0x3a, 0x20, 0xff, 0xfe])
  }
  Object.entries(mismatchedContent).forEach(([originalname, buffer]) => {
    it(`should reject ${originalname} whose content does not match its extension`, () => {
      challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
      req.file = { originalname, buffer }

      checkFileType(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(next.called).to.equal(false)
      expect(challenges.uploadTypeChallenge.solved).to.equal(false)
    })
  })
})
