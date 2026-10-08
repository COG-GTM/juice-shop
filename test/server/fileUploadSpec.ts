/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import path from 'node:path'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, resolveComplaintPath } from '../../routes/fileUpload'

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

    it('resolves plain and nested entries inside uploads/complaints', () => {
      expect(resolveComplaintPath('complaint.pdf')).to.equal(path.join(complaintsDir, 'complaint.pdf'))
      expect(resolveComplaintPath('report/page.pdf')).to.equal(path.join(complaintsDir, 'report', 'page.pdf'))
      expect(resolveComplaintPath('..complaint.pdf')).to.equal(path.join(complaintsDir, '..complaint.pdf'))
    })

    const rejected = [
      '../../ftp/legal.md',
      '../../frontend/dist/frontend/main.js',
      '../../frontend/dist/frontend/assets/public/videos/owasp_promo.vtt',
      '../../server.ts',
      '..\\..\\ftp\\legal.md',
      'report/../../../ftp/legal.md',
      'report/..',
      '..',
      '.',
      '',
      '/etc/passwd',
      path.resolve('ftp/legal.md'),
      'C:\\Windows\\win.ini',
      'complaint.pdf\0.js'
    ]
    rejected.forEach(fileName => {
      it(`rejects ${JSON.stringify(fileName)}`, () => {
        expect(resolveComplaintPath(fileName)).to.equal(null)
      })
    })

    it('rejects non-string entry paths', () => {
      expect(resolveComplaintPath(undefined)).to.equal(null)
      expect(resolveComplaintPath(42)).to.equal(null)
    })
  })
})
