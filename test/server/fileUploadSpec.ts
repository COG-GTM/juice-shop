/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { Writable } from 'node:stream'
import chai from 'chai'
import sinon from 'sinon'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, handleZipFileUpload } from '../../routes/fileUpload'

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

  it('should solve "uploadTypeChallenge" when file type is not PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.exe'

    checkFileType(req, res, () => {})

    expect(challenges.uploadTypeChallenge.solved).to.equal(true)
  })

  it('should not solve "uploadTypeChallenge" when file type is PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.pdf'

    checkFileType(req, res, () => {})

    expect(challenges.uploadTypeChallenge.solved).to.equal(false)
  })

  describe('handleZipFileUpload', () => {
    afterEach(() => {
      sinon.restore()
    })

    it('extracts the uploaded zip from memory without writing the upload to a temporary file', (done) => {
      challenges.fileWriteChallenge = { solved: false, save } as unknown as Challenge
      const zip = fs.readFileSync(path.resolve(__dirname, '../files/arbitraryFileWrite.zip'))
      const open = sinon.spy(fs, 'open')
      const write = sinon.spy(fs, 'write')
      const chunks: Buffer[] = []
      const createWriteStream = sinon.stub(fs, 'createWriteStream').callsFake(() => new Writable({
        write (chunk, _encoding, callback) {
          chunks.push(chunk)
          callback()
        },
        final (callback) {
          callback()
          try {
            expect(open.called).to.equal(false)
            expect(write.called).to.equal(false)
            expect(createWriteStream.calledOnceWith('uploads/complaints/../../ftp/legal.md')).to.equal(true)
            expect(Buffer.concat(chunks).length).to.equal(73)
            expect(challenges.fileWriteChallenge.solved).to.equal(true)
            done()
          } catch (err) {
            done(err)
          }
        }
      }) as unknown as fs.WriteStream)
      res.status = () => res
      res.end = () => {}
      req.file = { originalname: 'Complaint.ZIP', buffer: zip, size: zip.length }

      handleZipFileUpload(req, res, done)
    })
  })
})
