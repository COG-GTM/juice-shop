/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType } from '../../routes/fileUpload'

const expect = chai.expect

describe('fileUpload', () => {
  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    req = { file: { originalname: '' } }
    res = {}
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

        checkUploadSize(req, res, () => {})

        expect(challenges.uploadSizeChallenge.solved).to.equal(false)
      })
    })
  })

  it('should solve "uploadSizeChallenge" when file size exceeds 100000 bytes', () => {
    challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
    req.file.size = 100001

    checkUploadSize(req, res, () => {})

    expect(challenges.uploadSizeChallenge.solved).to.equal(true)
  })

  describe('checkFileType', () => {
    let status: number | undefined
    let nextCalled: boolean

    beforeEach(() => {
      status = undefined
      nextCalled = false
      res = {
        status (code: number) { status = code; return this },
        json () { return this }
      }
    })

    const next = () => { nextCalled = true }

    it('should accept a PDF file with matching content', async () => {
      req.file = { originalname: 'complaint.pdf', buffer: Buffer.from('%PDF-1.4\n%âãÏÓ\n1 0 obj\n') }

      await checkFileType(req, res, next)

      expect(nextCalled).to.equal(true)
      expect(status).to.equal(undefined)
    })

    it('should reject a file with a non-allowlisted extension', async () => {
      req.file = { originalname: 'hack.exe', buffer: Buffer.from('MZ') }

      await checkFileType(req, res, next)

      expect(nextCalled).to.equal(false)
      expect(status).to.equal(415)
    })

    it('should reject a file whose content does not match its PDF extension', async () => {
      req.file = { originalname: 'hack.pdf', buffer: Buffer.from('<html><script>alert(1)</script></html>') }

      await checkFileType(req, res, next)

      expect(nextCalled).to.equal(false)
      expect(status).to.equal(415)
    })

    for (const name of ['xxe.xml', 'bomb.yml', 'bomb.yaml']) {
      it(`should reject deprecated ${name} uploads without parsing them`, async () => {
        challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
        req.file = { originalname: name, buffer: Buffer.from('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>') }

        await checkFileType(req, res, next)

        expect(nextCalled).to.equal(false)
        expect(status).to.equal(410)
        expect(challenges.deprecatedInterfaceChallenge.solved).to.equal(true)
      })
    }
  })
})
