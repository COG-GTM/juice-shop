/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import os from 'node:os'
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
    const repoRoot = process.cwd()
    let sandbox: string

    function uploadZip (fixture: string) {
      const buffer = fs.readFileSync(path.resolve(repoRoot, 'test/files', fixture))
      return new Promise<void>((resolve, reject) => {
        const res: any = { status: () => ({ end: () => { setTimeout(resolve, 500) } }) }
        handleZipFileUpload({ file: { originalname: fixture, buffer } } as any, res, reject)
      })
    }

    beforeEach(() => {
      challenges.fileWriteChallenge = { solved: false, save } as unknown as Challenge
      sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-shop-zip-'))
      fs.mkdirSync(path.join(sandbox, 'uploads/complaints'), { recursive: true })
      fs.mkdirSync(path.join(sandbox, 'uploads/complaints-evil'), { recursive: true })
      fs.mkdirSync(path.join(sandbox, 'ftp'))
      fs.writeFileSync(path.join(sandbox, 'ftp/legal.md'), 'original')
      process.chdir(sandbox)
    })

    afterEach(() => {
      process.chdir(repoRoot)
      fs.rmSync(sandbox, { recursive: true, force: true })
    })

    it('should extract regular entries into the complaints directory', async () => {
      await uploadZip('validComplaintArchive.zip')

      expect(fs.readFileSync(path.join(sandbox, 'uploads/complaints/receipt.txt'), 'utf8')).to.equal('Proof of purchase attached.\n')
    })

    it('should not write entries traversing out of the complaints directory', async () => {
      await uploadZip('arbitraryFileWrite.zip')

      expect(fs.readFileSync(path.join(sandbox, 'ftp/legal.md'), 'utf8')).to.equal('original')
      expect(challenges.fileWriteChallenge.solved).to.equal(true)
    })

    it('should not write entries into sibling directories sharing the complaints path prefix', async () => {
      await uploadZip('siblingDirTraversal.zip')

      expect(fs.existsSync(path.join(sandbox, 'uploads/complaints-evil/pwned.txt'))).to.equal(false)
    })
  })
})
