/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import sinon from 'sinon'
import chai from 'chai'
const expect = chai.expect

function loadChecksumTask (): () => void {
  const tasks: Record<string, () => void> = {}
  const log: any = { write: () => log, writeln: () => log, ok: () => log }
  log.verbose = log
  const grunt = {
    option: () => undefined,
    initConfig: () => {},
    loadNpmTasks: () => {},
    registerTask: (name: string, ...args: any[]) => { tasks[name] = args[args.length - 1] },
    file: {
      readJSON: () => ({}),
      write: (file: string, content: string) => { fs.writeFileSync(file, content) }
    },
    log
  }
  require(path.resolve(__dirname, '../../Gruntfile.js'))(grunt)
  return tasks.checksum
}

describe('grunt checksum task', () => {
  const cwd = process.cwd()
  let tmp: string

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'checksum-'))
    process.chdir(tmp)
    fs.mkdirSync('dist')
    fs.writeFileSync('dist/juice-shop.zip', 'ZIPDATA')
  })

  afterEach(() => {
    sinon.restore()
    process.chdir(cwd)
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  it('writes SHA-256 checksum files for packaged archives', () => {
    loadChecksumTask()()

    expect(fs.readFileSync('dist/juice-shop.zip.sha256', 'utf8')).to.equal(crypto.createHash('sha256').update('ZIPDATA').digest('hex'))
    expect(fs.existsSync('dist/juice-shop.zip.md5')).to.equal(false)
  })

  it('never uses MD5 for checksums', () => {
    const createHash = sinon.spy(crypto, 'createHash')

    loadChecksumTask()()

    expect(createHash.called).to.equal(true)
    expect(createHash.args.map(args => String(args[0]).toLowerCase())).to.not.include('md5')
  })

  it('does not checksum existing .sha256 files', () => {
    fs.writeFileSync('dist/juice-shop.zip.sha256', 'stale')

    loadChecksumTask()()

    expect(fs.existsSync('dist/juice-shop.zip.sha256.sha256')).to.equal(false)
    expect(fs.readFileSync('dist/juice-shop.zip.sha256', 'utf8')).to.equal(crypto.createHash('sha256').update('ZIPDATA').digest('hex'))
  })
})
