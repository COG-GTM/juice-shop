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

const MAX_ZIP_ENTRIES = 100

// Minimal stored-mode (uncompressed) zip writer, so the extraction limits can be
// exercised without checking large fixture archives into the repository.
function zipOf (files: ReadonlyArray<readonly [string, Buffer]>): Buffer {
  const locals: Buffer[] = []
  const central: Buffer[] = []
  let offset = 0
  for (const [name, data] of files) {
    const nameBuf = Buffer.from(name)
    const crc = crc32(data)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(data.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(nameBuf.length, 26)
    locals.push(local, nameBuf, data)
    const entry = Buffer.alloc(46)
    entry.writeUInt32LE(0x02014b50, 0)
    entry.writeUInt16LE(20, 6)
    entry.writeUInt32LE(crc, 16)
    entry.writeUInt32LE(data.length, 20)
    entry.writeUInt32LE(data.length, 24)
    entry.writeUInt16LE(nameBuf.length, 28)
    entry.writeUInt32LE(offset, 42)
    central.push(entry, nameBuf)
    offset += local.length + nameBuf.length + data.length
  }
  const centralBuf = Buffer.concat(central)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(files.length, 8)
  end.writeUInt16LE(files.length, 10)
  end.writeUInt32LE(centralBuf.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([...locals, centralBuf, end])
}

function crc32 (buf: Buffer): number {
  let crc = ~0
  for (const byte of buf) {
    crc ^= byte
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (0xEDB88320 & -(crc & 1))
  }
  return (~crc) >>> 0
}

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
    let legalExisted: boolean
    let legalBefore: string

    beforeEach(() => {
      legalExisted = fs.existsSync(legalFile)
      if (!legalExisted) fs.copyFileSync(path.resolve('data/static/legal.md'), legalFile)
      legalBefore = fs.readFileSync(legalFile, 'utf8')
    })

    afterEach(() => {
      if (legalExisted) fs.writeFileSync(legalFile, legalBefore)
      else fs.rmSync(legalFile, { force: true })
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

    it('extracts at most MAX_ZIP_ENTRIES files from one archive', async () => {
      challenges.fileWriteChallenge = { solved: false, save } as unknown as Challenge
      req.file = { originalname: 'manyEntries.zip', buffer: zipOf(Array.from({ length: MAX_ZIP_ENTRIES + 1 }, (_, i) => [`entry${i}.txt`, Buffer.from('x')] as const)) }
      res = { status () { return { end () {} } } }

      handleZipFileUpload(req, res, () => {})
      await new Promise(resolve => setTimeout(resolve, 1000))
      const written = Array.from({ length: MAX_ZIP_ENTRIES + 1 }, (_, i) => `entry${i}.txt`).filter(name => fs.existsSync(path.resolve('uploads/complaints', name)))

      try {
        expect(written).to.have.lengthOf(MAX_ZIP_ENTRIES)
        expect(written).to.not.include(`entry${MAX_ZIP_ENTRIES}.txt`)
      } finally {
        for (const name of written) fs.rmSync(path.resolve('uploads/complaints', name), { force: true })
      }
    }).timeout(10000)

    it('discards an entry beyond the total size cap without destroying an existing complaint', async () => {
      challenges.fileWriteChallenge = { solved: false, save } as unknown as Challenge
      const complaintsDir = path.resolve('uploads/complaints')
      const existing = path.join(complaintsDir, 'existingComplaint.txt')
      fs.mkdirSync(complaintsDir, { recursive: true })
      fs.writeFileSync(existing, 'original complaint')
      req.file = { originalname: 'oversized.zip', buffer: zipOf([['existingComplaint.txt', Buffer.alloc(11 * 1024 * 1024, 0x79)]]) }
      res = { status () { return { end () {} } } }

      handleZipFileUpload(req, res, () => {})
      await new Promise(resolve => setTimeout(resolve, 1500))

      try {
        expect(fs.readFileSync(existing, 'utf8')).to.equal('original complaint')
        expect(fs.readdirSync(complaintsDir).filter(name => name.endsWith('.part'))).to.deep.equal([])
      } finally {
        fs.rmSync(existing, { force: true })
      }
    }).timeout(10000)

    it('replaces a symlink inside uploads/complaints instead of writing through it', async function () {
      if (process.platform === 'win32') this.skip()
      challenges.fileWriteChallenge = { solved: false, save } as unknown as Challenge
      const complaintsDir = path.resolve('uploads/complaints')
      const link = path.join(complaintsDir, 'linkedComplaint.txt')
      fs.mkdirSync(complaintsDir, { recursive: true })
      fs.rmSync(link, { force: true })
      fs.symlinkSync(legalFile, link)
      req.file = { originalname: 'symlink.zip', buffer: zipOf([['linkedComplaint.txt', Buffer.from('overwritten through symlink')]]) }
      res = { status () { return { end () {} } } }

      handleZipFileUpload(req, res, () => {})
      await new Promise(resolve => setTimeout(resolve, 500))

      try {
        expect(fs.readFileSync(legalFile, 'utf8')).to.equal(legalBefore)
        expect(fs.lstatSync(link).isSymbolicLink()).to.equal(false)
        expect(fs.readFileSync(link, 'utf8')).to.equal('overwritten through symlink')
      } finally {
        fs.rmSync(link, { force: true })
      }
    }).timeout(10000)
  })
})
