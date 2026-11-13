/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import type { Request, Response } from 'express'
import { checkKeys, nftUnlocked } from '../../routes/checkKeys'
const expect = chai.expect

describe('checkKeys', () => {
  function fakeResponse (failFirstJson = false) {
    const sent: Array<{ status?: number, body: unknown }> = []
    let status: number | undefined
    const res = {
      status (code: number) { status = code; return this },
      json (body: unknown) {
        if (failFirstJson && sent.length === 0 && status === 200) {
          failFirstJson = false
          throw new Error('Internal failure at /app/routes/checkKeys.ts:36:23')
        }
        sent.push({ status, body })
      }
    }
    return { res: res as unknown as Response, sent }
  }

  it('responds with a generic 500 instead of the internal error when checking a key fails', async () => {
    const { res, sent } = fakeResponse()

    await checkKeys()({} as unknown as Request, res)

    expect(sent).to.deep.equal([{ status: 500, body: 'Internal Server Error' }])
  })

  it('responds with a generic 500 instead of the internal error when the unlock status cannot be sent', () => {
    const { res, sent } = fakeResponse(true)

    nftUnlocked()({} as unknown as Request, res)

    expect(sent).to.deep.equal([{ status: 500, body: 'Internal Server Error' }])
  })
})
