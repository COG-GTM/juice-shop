/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
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
    beforeEach(() => {
      challenges.fileWriteChallenge = { solved: false, save } as unknown as Challenge
      res = { status: () => ({ end () {} }) }
    })

    afterEach(() => {
      sinon.restore()
    })

    it('should pass the error to next instead of crashing when the temp file cannot be opened', (done) => {
      const openError = new Error('ENAMETOOLONG')
      sinon.stub(fs, 'open').callsFake(((_path: fs.PathLike, _flags: fs.OpenMode, cb: (err: Error | null, fd?: number) => void) => {
        setImmediate(() => { cb(openError) })
      }) as unknown as typeof fs.open)
      const write = sinon.spy(fs, 'write')
      req.file = { originalname: 'a'.repeat(300) + '.zip', buffer: Buffer.from('not a zip') }

      handleZipFileUpload(req, res, (err?: unknown) => {
        expect(err).to.equal(openError)
        setImmediate(() => {
          expect(write.called).to.equal(false)
          done()
        })
      })
    })

    it('should use a server-generated temp file name and remove the temp file afterwards', (done) => {
      const open = sinon.spy(fs, 'open')
      const originalname = 'a'.repeat(300) + '.zip'
      req.file = { originalname, buffer: fs.readFileSync(path.resolve(__dirname, '../files/passwordProtected.zip')) }

      handleZipFileUpload(req, res, () => {})

      const tempFile = open.firstCall.args[0] as string
      expect(path.dirname(tempFile)).to.equal(os.tmpdir())
      expect(tempFile).to.not.include(originalname)
      const waitForCleanup = setInterval(() => {
        if (!fs.existsSync(tempFile)) {
          clearInterval(waitForCleanup)
          done()
        }
      }, 10)
    })
  })
})
