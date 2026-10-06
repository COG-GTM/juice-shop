/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import crypto from 'node:crypto'
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
    it('should resolve plain entry names inside the complaints directory', () => {
      expect(resolveComplaintPath('complaint.pdf')).to.equal(path.resolve('uploads/complaints/complaint.pdf'))
      expect(resolveComplaintPath('sub/complaint.pdf')).to.equal(path.resolve('uploads/complaints/sub/complaint.pdf'))
    })

    const maliciousNames = [
      '../../ftp/legal.md',
      '../../frontend/dist/frontend/assets/public/videos/owasp_promo.vtt',
      'sub/../../complaints2/x',
      '..\\..\\ftp\\legal.md',
      '..',
      '/etc/passwd',
      path.resolve('ftp/legal.md'),
      '',
      '.'
    ]
    maliciousNames.forEach(name => {
      it(`should reject "${name}"`, () => {
        expect(resolveComplaintPath(name)).to.equal(null)
      })
    })
  })

  describe('handleZipFileUpload', () => {
    const marker = crypto.randomBytes(6).toString('hex')
    const traversalTarget = path.resolve(`ftp/zip-slip-${marker}.md`)
    const legitTarget = path.resolve(`uploads/complaints/zip-slip-${marker}.txt`)

    const originalFileWriteChallenge = challenges.fileWriteChallenge

    afterEach(() => {
      challenges.fileWriteChallenge = originalFileWriteChallenge
      fs.rmSync(traversalTarget, { force: true })
      fs.rmSync(legitTarget, { force: true })
    })

    it('should not write ZIP entries outside of uploads/complaints', async () => {
      challenges.fileWriteChallenge = { solved: false, save } as unknown as Challenge
      req.file = {
        originalname: 'complaint.zip',
        buffer: createZip({
          [`../../ftp/zip-slip-${marker}.md`]: 'overwritten',
          [`zip-slip-${marker}.txt`]: 'complaint'
        })
      }
      res = { status: () => ({ end: () => {} }) }

      handleZipFileUpload(req, res, () => {})

      await waitFor(() => fs.existsSync(legitTarget) && fs.readFileSync(legitTarget, 'utf8') === 'complaint')
      await new Promise(resolve => setTimeout(resolve, 200))
      expect(fs.existsSync(traversalTarget)).to.equal(false)
    })
  })
})

function createZip (entries: Record<string, string>) {
  const localParts: Buffer[] = []
  const centralParts: Buffer[] = []
  let offset = 0
  for (const [name, content] of Object.entries(entries)) {
    const nameBuffer = Buffer.from(name)
    const data = Buffer.from(content)
    const crc = zlib.crc32(data)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(data.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(nameBuffer.length, 26)
    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(data.length, 20)
    central.writeUInt32LE(data.length, 24)
    central.writeUInt16LE(nameBuffer.length, 28)
    central.writeUInt32LE(offset, 42)
    localParts.push(local, nameBuffer, data)
    centralParts.push(central, nameBuffer)
    offset += local.length + nameBuffer.length + data.length
  }
  const centralDirectory = Buffer.concat(centralParts)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(centralParts.length / 2, 8)
  end.writeUInt16LE(centralParts.length / 2, 10)
  end.writeUInt32LE(centralDirectory.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([...localParts, centralDirectory, end])
}

async function waitFor (condition: () => boolean, timeoutMs = 5000) {
  const start = Date.now()
  while (!condition()) {
    if (Date.now() - start > timeoutMs) throw new Error('Timed out waiting for ZIP extraction')
    await new Promise(resolve => setTimeout(resolve, 25))
  }
}
