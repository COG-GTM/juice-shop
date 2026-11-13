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

const md5 = (content: string) => crypto.createHash('md5').update(content).digest('hex')

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
  let checksum: () => void

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'checksum-'))
    process.chdir(tmp)
    fs.mkdirSync('dist')
    fs.writeFileSync('dist/a.zip', 'ZIPDATA')
    fs.writeFileSync('dist/b.tgz', 'TGZDATA')
    fs.writeFileSync('secret.txt', 'TOP SECRET')
    checksum = loadChecksumTask()
  })

  afterEach(() => {
    sinon.restore()
    process.chdir(cwd)
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  it('writes checksums for archives and skips directories and existing .md5 files', () => {
    fs.mkdirSync('dist/subdir')
    fs.writeFileSync('dist/a.zip.md5', 'stale')

    checksum()

    expect(fs.readdirSync('dist').sort()).to.deep.equal(['a.zip', 'a.zip.md5', 'b.tgz', 'b.tgz.md5', 'subdir'])
    expect(fs.readFileSync('dist/a.zip.md5', 'utf8')).to.equal(md5('ZIPDATA'))
    expect(fs.readFileSync('dist/b.tgz.md5', 'utf8')).to.equal(md5('TGZDATA'))
  })

  if (process.platform !== 'win32') {
    it('does not follow a symlink swapped in after the directory listing', () => {
      const readdirSync = fs.readdirSync
      sinon.stub(fs, 'readdirSync').callsFake((...args: any[]) => {
        const entries = (readdirSync as any)(...args)
        fs.unlinkSync('dist/b.tgz')
        fs.symlinkSync(path.resolve('secret.txt'), 'dist/b.tgz')
        return entries
      })

      checksum()

      expect(fs.readFileSync('dist/a.zip.md5', 'utf8')).to.equal(md5('ZIPDATA'))
      expect(fs.existsSync('dist/b.tgz.md5')).to.equal(false)
    })

    it('hashes the file that was opened even if the path is replaced afterwards', () => {
      const openSync = fs.openSync
      sinon.stub(fs, 'openSync').callsFake((...args: any[]) => {
        const fd = (openSync as any)(...args)
        if (String(args[0]).endsWith('b.tgz')) {
          fs.renameSync('dist/b.tgz', 'b.tgz.orig')
          fs.writeFileSync('dist/b.tgz', 'ATTACKER CONTENT')
        }
        return fd
      })

      checksum()

      expect(fs.readFileSync('dist/b.tgz.md5', 'utf8')).to.equal(md5('TGZDATA'))
    })
  }
})
