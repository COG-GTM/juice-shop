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
import { checkUploadSize, checkFileType, resolveComplaintEntryPath, createExtractionBudget, isReachableWithoutSymlinks, publishAtomically } from '../../routes/fileUpload'

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
      '../../ftp/x.md',
      '../../i18n/en.json',
      '../../data/static/codefixes/x.info.yml',
      '../../frontend/dist/frontend/index.html',
      '../../frontend/dist/frontend/main.js',
      '../../build/routes/login.js',
      '../../node_modules/svg-captcha/index.js',
      '../../node_modules/pug/lib/index.js',
      '../../data/static/users.yml',
      '../../config/default.yml',
      '../../node_modules/pdfkit/js/pdfkit.js',
      '../../test-zip-slip.txt',
      '../../views/promotionVideo.pug',
      '../../views/userProfile.pug',
      'uploads/../../../views/userProfile.pug',
      '../../routes/userProfile.ts',
      '../../views/test.txt',
      '../../uploads/complaints/../../views/promotionVideo.pug',
      '../x',
      'nested/../../../views/promotionVideo.pug',
      './../../views/promotionVideo.pug',
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
      'complaint.pdf\0.txt',
      `../../../${path.basename(path.resolve('.'))}-evil/x.txt`,
      path.resolve('.') + '-evil/x.txt',
      '.upload-00000000-0000-4000-8000-000000000000.part',
      './.UPLOAD-x.PART'
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

    it('should still accept entries after exactly 10 MB uncompressed', (done) => {
      const budget = createExtractionBudget()
      expect(budget.takeEntry()).to.equal(true)
      Readable.from(Array.from({ length: 10 }, () => Buffer.alloc(1024 * 1024))).pipe(budget.limiter()).on('error', done).on('finish', () => {
        expect(budget.takeEntry()).to.equal(true)
        done()
      }).resume()
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

  describe('publishAtomically', () => {
    const complaintsDirectory = path.resolve('uploads/complaints')
    const id = `${process.pid}-${Date.now()}`
    const existing = path.join(complaintsDirectory, `existing-${id}.pdf`)
    const fresh = path.join(complaintsDirectory, `fresh-${id}.pdf`)
    const failing = path.join(complaintsDirectory, `failing-${id}.pdf`)
    const staged = (name: string, content: string) => {
      const tempPath = path.join(complaintsDirectory, `.upload-${name}-${id}.part`)
      fs.writeFileSync(tempPath, content)
      return tempPath
    }
    const originalRename = fs.promises.rename

    beforeEach(() => {
      fs.mkdirSync(complaintsDirectory, { recursive: true })
      fs.writeFileSync(existing, 'OLD')
    })

    afterEach(() => {
      fs.promises.rename = originalRename
      for (const file of fs.readdirSync(complaintsDirectory)) {
        if (file.includes(id)) fs.rmSync(path.join(complaintsDirectory, file), { force: true })
      }
    })

    it('should publish every staged entry and drop backups of overwritten files', async () => {
      const entries = [{ tempPath: staged('a', 'NEW'), targetPath: existing }, { tempPath: staged('b', 'FRESH'), targetPath: fresh }]
      expect(await publishAtomically(entries, () => false)).to.equal(true)
      expect(fs.readFileSync(existing, 'utf8')).to.equal('NEW')
      expect(fs.readFileSync(fresh, 'utf8')).to.equal('FRESH')
      expect(fs.readdirSync(complaintsDirectory).filter(file => file.includes(id) && file.endsWith('.part'))).to.deep.equal([])
    })

    it('should roll back already published entries when a later rename fails', async () => {
      fs.promises.rename = (async (from: fs.PathLike, to: fs.PathLike) => {
        if (to === failing) throw new Error('EIO: simulated rename failure')
        await originalRename(from, to)
      }) as typeof fs.promises.rename
      const entries = [
        { tempPath: staged('a', 'NEW'), targetPath: existing },
        { tempPath: staged('b', 'FRESH'), targetPath: fresh },
        { tempPath: staged('c', 'FAIL'), targetPath: failing }
      ]
      expect(await publishAtomically(entries, () => false)).to.equal(false)
      expect(fs.readFileSync(existing, 'utf8')).to.equal('OLD')
      expect(fs.existsSync(fresh)).to.equal(false)
      expect(fs.existsSync(failing)).to.equal(false)
      expect(fs.readdirSync(complaintsDirectory).filter(file => file.includes(id) && file.endsWith('.part'))).to.deep.equal([])
    })

    it('should keep the backup of an overwritten file when restoring it fails', async () => {
      fs.promises.rename = (async (from: fs.PathLike, to: fs.PathLike) => {
        const isBackupRestore = to === existing && !String(from).includes(id)
        if (to === failing || isBackupRestore) throw new Error('EACCES: simulated rename failure')
        await originalRename(from, to)
      }) as typeof fs.promises.rename
      const entries = [{ tempPath: staged('a', 'NEW'), targetPath: existing }, { tempPath: staged('c', 'FAIL'), targetPath: failing }]
      expect(await publishAtomically(entries, () => false)).to.equal(false)
      const backups = fs.readdirSync(complaintsDirectory).filter(file => /^\.upload-.*\.part$/.test(file) && !file.includes(id)).map(file => path.join(complaintsDirectory, file))
      try {
        expect(backups.map(file => fs.readFileSync(file, 'utf8'))).to.include('OLD')
      } finally {
        backups.forEach(file => { fs.rmSync(file, { force: true }) })
      }
    })

    it('should not let a failing upload roll back over a concurrent successful upload of the same file', async () => {
      fs.promises.rename = (async (from: fs.PathLike, to: fs.PathLike) => {
        if (to === failing) throw new Error('EIO: simulated rename failure')
        await originalRename(from, to)
      }) as typeof fs.promises.rename
      const failingUpload = publishAtomically([{ tempPath: staged('a', 'A'), targetPath: existing }, { tempPath: staged('c', 'FAIL'), targetPath: failing }], () => false)
      const successfulUpload = publishAtomically([{ tempPath: staged('b', 'B'), targetPath: existing }], () => false)
      expect(await Promise.all([failingUpload, successfulUpload])).to.deep.equal([false, true])
      expect(fs.readFileSync(existing, 'utf8')).to.equal('B')
    })
  })
})
