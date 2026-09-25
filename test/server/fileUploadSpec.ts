/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import fs from 'node:fs'
import path from 'node:path'
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

  describe('resolveComplaintPath', () => {
    it('should reject entry names escaping the complaints directory', () => {
      const names = ['../../ftp/legal.md', '..\\..\\ftp\\legal.md', 'a/../../legal.md', '/etc/passwd', '']
      names.forEach(name => {
        expect(resolveComplaintPath(name)).to.equal(null)
      })
    })

    it('should resolve entry names inside the complaints directory', () => {
      expect(resolveComplaintPath('complaint.pdf')).to.equal(path.resolve('uploads/complaints/complaint.pdf'))
      expect(resolveComplaintPath('nested/complaint.pdf')).to.equal(path.resolve('uploads/complaints/nested/complaint.pdf'))
      expect(resolveComplaintPath('..complaint.pdf')).to.equal(path.resolve('uploads/complaints/..complaint.pdf'))
    })

    it('should allow only the promotion video subtitles outside the complaints directory', () => {
      expect(resolveComplaintPath('../../frontend/dist/frontend/assets/public/videos/owasp_promo.vtt')).to.equal(path.resolve('frontend/dist/frontend/assets/public/videos/owasp_promo.vtt'))
      expect(resolveComplaintPath('../../frontend/dist/frontend/assets/public/videos/owasp_promo.mp4')).to.equal(null)
    })

    it('should reject entry names below a symlinked sub-directory', () => {
      const link = path.resolve('uploads/complaints/escape-link')
      fs.symlinkSync(path.resolve('ftp'), link, 'dir')
      try {
        expect(resolveComplaintPath('escape-link/legal.md')).to.equal(null)
      } finally {
        fs.unlinkSync(link)
      }
    })
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
})
