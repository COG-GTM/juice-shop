/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import chai from 'chai'
import cleanupFtpFolder from '../../lib/startup/cleanupFtpFolder'
const expect = chai.expect

describe('cleanupFtpFolder', () => {
  const ftpPdf = 'ftp/order_cleanup-spec.pdf'
  const ordersPdf = 'orders/order_cleanup-spec.pdf'
  const ordersNonPdf = 'orders/cleanup-spec.txt'

  beforeEach(() => {
    fs.mkdirSync('orders', { recursive: true })
    for (const file of [ftpPdf, ordersPdf, ordersNonPdf]) {
      fs.writeFileSync(file, '')
    }
  })

  afterEach(() => {
    for (const file of [ftpPdf, ordersPdf, ordersNonPdf]) {
      fs.rmSync(file, { force: true })
    }
  })

  it('removes order confirmation PDFs from ftp and orders folders', async () => {
    await cleanupFtpFolder()

    expect(fs.existsSync(ftpPdf)).to.equal(false)
    expect(fs.existsSync(ordersPdf)).to.equal(false)
  })

  it('keeps non-PDF files in orders folder', async () => {
    await cleanupFtpFolder()

    expect(fs.existsSync(ordersNonPdf)).to.equal(true)
  })
})
