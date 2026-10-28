/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import * as models from '../../models/index'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { searchProducts } from '../../routes/search'
const expect = chai.expect
chai.use(sinonChai)

describe('search', () => {
  const payload = "x')) UNION SELECT id,email,password,totpSecret,role,'5','6','7','8' FROM Users--"
  let req: any
  let res: any
  let next: any
  let query: sinon.SinonStub

  const flush = async () => { await new Promise(resolve => setImmediate(resolve)) }

  beforeEach(() => {
    req = { query: { q: payload }, __: (s: string) => s }
    res = { json: sinon.spy() }
    next = sinon.spy()
    challenges.unionSqlInjectionChallenge = { solved: true } as unknown as Challenge
    challenges.dbSchemaChallenge = { solved: true } as unknown as Challenge
    query = sinon.stub(models.sequelize, 'query')
  })

  afterEach(() => {
    sinon.restore()
  })

  it('passes the search term as a bound replacement instead of splicing it into the SQL', async () => {
    query.resolves([[]])

    searchProducts()(req, res, next)
    await flush()

    expect(query.callCount).to.equal(1)
    const [sql, options] = query.firstCall.args
    expect(sql).to.not.include(payload)
    expect(sql).to.include(':criteria')
    expect(options).to.deep.equal({ replacements: { criteria: `%${payload}%` } })
    expect(res.json.calledOnce).to.equal(true)
  })

  it('treats a non-string q parameter like an empty search', async () => {
    req.query.q = [payload, 'x']
    query.resolves([[]])

    searchProducts()(req, res, next)
    await flush()

    expect(query.firstCall.args[1]).to.deep.equal({ replacements: { criteria: '%%' } })
  })

  it('does not forward the underlying database error to the error handler', async () => {
    const dbError: any = new Error('SQLITE_ERROR: near "UNION": syntax error')
    dbError.sql = `SELECT * FROM Products WHERE name LIKE '%${payload}%'`
    const error: any = new Error('DatabaseError')
    error.parent = dbError
    query.rejects(error)

    searchProducts()(req, res, next)
    await flush()

    expect(next.calledOnce).to.equal(true)
    const forwarded = next.firstCall.args[0]
    expect(forwarded).to.be.an('error')
    expect(forwarded).to.not.equal(dbError)
    expect(forwarded.message).to.equal('Product search failed')
    expect(forwarded.sql).to.equal(undefined)
    expect(res.json.called).to.equal(false)
  })
})
