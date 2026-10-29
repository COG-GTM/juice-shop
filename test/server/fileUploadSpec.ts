/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import path from 'node:path'
import fs from 'node:fs'
import os from 'node:os'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { Readable, Writable } from 'node:stream'
import { checkUploadSize, checkFileType, resolveComplaintEntryPath, createExtractionBudget, isReachableWithoutSymlinks } from '../../routes/fileUpload'

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

  describe('resolveComplaintEntryPath', () => {
    const complaintsDirectory = path.resolve('uploads/complaints')

    it('should resolve top-level entry names inside uploads/complaints', () => {
      expect(resolveComplaintEntryPath('complaint.pdf')).to.equal(path.join(complaintsDirectory, 'complaint.pdf'))
      expect(resolveComplaintEntryPath('./complaint.pdf')).to.equal(path.join(complaintsDirectory, 'complaint.pdf'))
    })

    const maliciousEntries = [
      '../../ftp/legal.md',
      '../../ftp/zipslip-test.md',
      '../../frontend/dist/frontend/index.html',
      '../../build/routes/login.js',
      '../../data/static/users.yml',
      '../../views/promotionVideo.pug',
      '../../views/userProfile.pug',
      'nested/../../../views/promotionVideo.pug',
      'nested/complaint.pdf',
      '../../frontend/dist/frontend/assets/public/videos/owasp_promo.vtt',
      '../complaints/../../server.ts',
      'nested/../../complaints-evil/x.txt',
      '..\\..\\ftp\\legal.md',
      '..',
      '.',
      '',
      '/etc/passwd',
      path.resolve('ftp/legal.md'),
      path.join(complaintsDirectory, 'absolute.txt'),
      'C:\\Windows\\win.ini',
      'C:relative.txt',
      '\\\\server\\share\\x.txt',
      'complaint.pdf\0.txt'
    ]
    maliciousEntries.forEach(entry => {
      it(`should reject entry ${JSON.stringify(entry)}`, () => {
        expect(resolveComplaintEntryPath(entry)).to.equal(null)
      })
    })

    it('should reject non-string entry names', () => {
      expect(resolveComplaintEntryPath(undefined)).to.equal(null)
      expect(resolveComplaintEntryPath(42)).to.equal(null)
    })
  })

  describe('createExtractionBudget', () => {
    it('should allow at most 100 entries per archive', () => {
      const budget = createExtractionBudget()
      const taken = Array.from({ length: 150 }, () => budget.takeEntry()).filter(Boolean)
      expect(taken.length).to.equal(100)
    })

    it('should still accept entries once exactly 10 MB have been extracted', (done) => {
      const budget = createExtractionBudget()
      const sink = new Writable({ write (_chunk: Buffer, _encoding, callback) { callback() } })
      Readable.from([Buffer.alloc(10 * 1024 * 1024)]).pipe(budget.limiter()).pipe(sink).on('finish', () => {
        expect(budget.takeEntry()).to.equal(true)
        done()
      })
    })

    it('should stop writing and fail once the archive exceeds 10 MB uncompressed', (done) => {
      const budget = createExtractionBudget()
      let written = 0
      const sink = new Writable({ write (chunk: Buffer, _encoding, callback) { written += chunk.length; callback() } })
      const chunks = Array.from({ length: 12 }, () => Buffer.alloc(1024 * 1024))
      Readable.from(chunks).pipe(budget.limiter()).on('error', (err: Error) => {
        expect(err.message).to.match(/uncompressed size limit/)
        expect(written).to.equal(10 * 1024 * 1024)
        expect(budget.takeEntry()).to.equal(false)
        done()
      }).pipe(sink)
    })
  })

  describe('isReachableWithoutSymlinks', () => {
    let root: string

    beforeEach(() => {
      root = fs.mkdtempSync(path.join(os.tmpdir(), 'complaints-'))
      fs.mkdirSync(path.join(root, 'app'))
      fs.mkdirSync(path.join(root, 'outside', 'complaints'), { recursive: true })
    })

    afterEach(() => {
      fs.rmSync(root, { recursive: true, force: true })
    })

    it('should accept a real uploads/complaints directory', () => {
      fs.mkdirSync(path.join(root, 'app', 'uploads', 'complaints'), { recursive: true })
      expect(isReachableWithoutSymlinks(path.join(root, 'app', 'uploads', 'complaints'))).to.equal(true)
    })

    it('should reject a symlinked uploads parent directory', () => {
      fs.symlinkSync(path.join(root, 'outside'), path.join(root, 'app', 'uploads'))
      expect(isReachableWithoutSymlinks(path.join(root, 'app', 'uploads', 'complaints'))).to.equal(false)
    })

    it('should reject a symlinked complaints directory', () => {
      fs.mkdirSync(path.join(root, 'app', 'uploads'))
      fs.symlinkSync(path.join(root, 'outside', 'complaints'), path.join(root, 'app', 'uploads', 'complaints'))
      expect(isReachableWithoutSymlinks(path.join(root, 'app', 'uploads', 'complaints'))).to.equal(false)
    })
  })
})
