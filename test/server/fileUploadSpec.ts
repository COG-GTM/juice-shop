/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import chai from 'chai'
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
    const complaintsDir = path.resolve('uploads/complaints')
    const legitFile = path.join(complaintsDir, 'zipSlipComplaint.txt')
    const escapedFile = path.resolve('uploads/zipSlipEscape.txt')

    const waitFor = async (condition: () => boolean, timeout = 5000) => {
      const start = Date.now()
      while (!condition()) {
        if (Date.now() - start > timeout) throw new Error('Timed out waiting for zip extraction')
        await new Promise(resolve => setTimeout(resolve, 50))
      }
    }

    const upload = (fixture: string) => {
      req.file = { originalname: fixture, buffer: fs.readFileSync(path.resolve('test/files', fixture)) }
      res = { status: () => ({ end () {} }) }
      handleZipFileUpload(req, res, () => {})
    }

    beforeEach(() => {
      challenges.fileWriteChallenge = { solved: false, save } as unknown as Challenge
    })

    afterEach(() => {
      fs.rmSync(legitFile, { force: true })
      fs.rmSync(escapedFile, { force: true })
    })

    it('should extract entries that stay inside uploads/complaints', async () => {
      upload('zipSlipMixed.zip')

      await waitFor(() => fs.existsSync(legitFile) && fs.readFileSync(legitFile, 'utf8') === 'legit complaint\n')
    })

    it('should not extract entries that traverse outside uploads/complaints', async () => {
      upload('zipSlipMixed.zip')

      await waitFor(() => fs.existsSync(legitFile))
      await new Promise(resolve => setTimeout(resolve, 200))
      expect(fs.existsSync(escapedFile)).to.equal(false)
    })

    it('should solve "fileWriteChallenge" without overwriting ftp/legal.md', async () => {
      const legalFile = path.resolve('ftp/legal.md')
      const original = fs.existsSync(legalFile) ? fs.readFileSync(legalFile, 'utf8') : null

      upload('arbitraryFileWrite.zip')

      await waitFor(() => challenges.fileWriteChallenge.solved)
      await new Promise(resolve => setTimeout(resolve, 200))
      expect(fs.existsSync(legalFile) ? fs.readFileSync(legalFile, 'utf8') : null).to.equal(original)
    })
  })
})
