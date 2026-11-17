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

  describe('should reject with 415 and not call next() when file type is', () => {
    const fileNames = ['hack.exe', 'hack.html', 'hack.pdf.exe', 'hack.svg', 'noextension']
    fileNames.forEach(fileName => {
      it(fileName, () => {
        challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
        req.file.originalname = fileName
        let statusCode: number | undefined
        res = { status: (code: number) => { statusCode = code; return res }, json: () => res }
        let nextCalled = false

        checkFileType(req, res, () => { nextCalled = true })

        expect(statusCode).to.equal(415)
        expect(nextCalled).to.equal(false)
        expect(challenges.uploadTypeChallenge.solved).to.equal(false)
      })
    })
  })

  describe('should accept and call next() when file type is', () => {
    const fileNames = ['hack.pdf', 'hack.PDF', 'hack.xml', 'hack.zip', 'hack.yml', 'hack.yaml']
    fileNames.forEach(fileName => {
      it(fileName, () => {
        req.file.originalname = fileName
        let nextCalled = false

        checkFileType(req, res, () => { nextCalled = true })

        expect(nextCalled).to.equal(true)
      })
    })
  })
})
