/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import chai from 'chai'
import cleanupFtpFolder from '../../lib/startup/cleanupFtpFolder'
const expect = chai.expect

describe('cleanupFtpFolder', () => {
  const originalCwd = process.cwd()
  let sandbox: string

  beforeEach(() => {
    sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-shop-cleanup-'))
    process.chdir(sandbox)
    fs.mkdirSync('ftp')
    fs.mkdirSync('orders')
    for (const file of ['ftp/order_a.pdf', 'orders/order_b.pdf', 'ftp/legal.md', 'orders/notes.txt']) {
      fs.writeFileSync(file, '')
    }
  })

  afterEach(() => {
    process.chdir(originalCwd)
    fs.rmSync(sandbox, { recursive: true, force: true })
  })

  it('removes order confirmation PDFs from ftp and orders folders', async () => {
    await cleanupFtpFolder()

    expect(fs.existsSync('ftp/order_a.pdf')).to.equal(false)
    expect(fs.existsSync('orders/order_b.pdf')).to.equal(false)
  })

  it('keeps non-PDF files', async () => {
    await cleanupFtpFolder()

    expect(fs.existsSync('ftp/legal.md')).to.equal(true)
    expect(fs.existsSync('orders/notes.txt')).to.equal(true)
  })
})
