/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import chai from 'chai'
import cleanupFtpFolder from '../../lib/startup/cleanupFtpFolder'
const expect = chai.expect

describe('cleanupFtpFolder', () => {
  const legacyPdf = path.join('ftp', 'order_cleanup-spec.pdf')
  const userDirectory = path.join('orders', 'cleanup-spec')
  const privatePdf = path.join(userDirectory, 'order_cleanup-spec.pdf')

  afterEach(() => {
    fs.rmSync(legacyPdf, { force: true })
    fs.rmSync(userDirectory, { recursive: true, force: true })
  })

  it('removes legacy order confirmations from ftp/ and private ones from orders/', async () => {
    fs.writeFileSync(legacyPdf, 'customer@juice-sh.op')
    fs.mkdirSync(userDirectory, { recursive: true })
    fs.writeFileSync(privatePdf, 'customer@juice-sh.op')

    await cleanupFtpFolder()

    expect(fs.existsSync(legacyPdf)).to.equal(false)
    expect(fs.existsSync(privatePdf)).to.equal(false)
    expect(fs.existsSync(path.join('ftp', 'legal.md'))).to.equal(true)
  })
})
