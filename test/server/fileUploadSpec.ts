/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import chai from 'chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, handleZipFileUpload, resolveComplaintPath } from '../../routes/fileUpload'

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

  describe('resolveComplaintPath', () => {
    const complaintsDir = path.resolve('uploads/complaints')

    it('resolves plain entry names inside uploads/complaints', () => {
      expect(resolveComplaintPath('complaint.pdf')).to.equal(path.join(complaintsDir, 'complaint.pdf'))
      expect(resolveComplaintPath('nested/complaint.pdf')).to.equal(path.join(complaintsDir, 'nested', 'complaint.pdf'))
    })

    const maliciousNames = [
      '../../ftp/legal.md',
      '../../frontend/dist/frontend/main.js',
      '../../frontend/dist/frontend/assets/public/videos/owasp_promo.vtt',
      'nested/../../../server.ts',
      '..\\..\\ftp\\legal.md',
      '..',
      '.',
      '/etc/passwd',
      'C:\\Windows\\win.ini',
      'complaint.pdf\0.js',
      ''
    ]
    maliciousNames.forEach(name => {
      it(`rejects entry name ${JSON.stringify(name)}`, () => {
        expect(resolveComplaintPath(name)).to.equal(null)
      })
    })

    it('rejects non-string entry names', () => {
      expect(resolveComplaintPath(undefined)).to.equal(null)
      expect(resolveComplaintPath(42)).to.equal(null)
    })
  })

  describe('handleZipFileUpload', () => {
    const legalFile = path.resolve('ftp/legal.md')
    let legalBefore: string

    beforeEach(() => {
      legalBefore = fs.readFileSync(legalFile, 'utf8')
    })

    afterEach(() => {
      fs.writeFileSync(legalFile, legalBefore)
    })

    it('does not overwrite ftp/legal.md from a zip entry with path traversal but still solves "fileWriteChallenge"', async () => {
      challenges.fileWriteChallenge = { solved: false, save } as unknown as Challenge
      req.file = { originalname: 'arbitraryFileWrite.zip', buffer: fs.readFileSync(path.resolve(__dirname, '../files/arbitraryFileWrite.zip')) }
      let status: number | undefined
      res = { status (code: number) { status = code; return { end () {} } } }
      const errors: unknown[] = []

      handleZipFileUpload(req, res, (err?: unknown) => { if (err !== undefined) errors.push(err) })
      for (let i = 0; i < 20 && !challenges.fileWriteChallenge.solved; i++) {
        await new Promise(resolve => setTimeout(resolve, 50))
      }
      await new Promise(resolve => setTimeout(resolve, 250))

      expect(status).to.equal(204)
      expect(errors).to.deep.equal([])
      expect(challenges.fileWriteChallenge.solved).to.equal(true)
      expect(fs.readFileSync(legalFile, 'utf8')).to.equal(legalBefore)
    })
  })
})
