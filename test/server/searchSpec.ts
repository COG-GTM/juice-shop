/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import * as models from '../../models/index'
import { UserModel } from '../../models/user'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import * as security from '../../lib/insecurity'
import { searchProducts } from '../../routes/search'
const expect = chai.expect
chai.use(sinonChai)

const users = [
  { email: 'admin@juice-sh.op', password: security.hash('admin123') },
  { email: 'jim@juice-sh.op', password: security.hash('ncc-1701') }
]
const tableDefinitions = [
  { sql: 'CREATE TABLE `Users` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `email` VARCHAR(255))' },
  { sql: null },
  { sql: 'CREATE TABLE sqlite_sequence(name,seq)' }
]
const products = [{ id: 1, name: 'Apple Juice (1000ml)', description: 'The all-time classic.' }]

describe('search', () => {
  let req: any
  let res: any
  let next: any
  let query: sinon.SinonStub
  let findAll: sinon.SinonStub

  const flush = async () => { await new Promise(resolve => setImmediate(resolve)) }
  const productsQuery = (rows: any[]) => query.withArgs(sinon.match(/^SELECT \* FROM Products/)).resolves([rows])

  beforeEach(() => {
    req = { query: { q: '' }, __: (s: string) => s }
    res = { json: sinon.spy() }
    next = sinon.spy()
    const save = () => ({ then () { } })
    challenges.unionSqlInjectionChallenge = { solved: false, save } as unknown as Challenge
    challenges.dbSchemaChallenge = { solved: false, save } as unknown as Challenge
    query = sinon.stub(models.sequelize, 'query')
    query.withArgs('SELECT sql FROM sqlite_master').resolves([tableDefinitions])
    findAll = sinon.stub(UserModel, 'findAll').resolves(users as any)
  })

  afterEach(() => {
    sinon.restore()
  })

  it('runs only the product query for a regular search', async () => {
    productsQuery(products)

    searchProducts()(req, res, next)
    await flush()

    expect(res.json).to.have.been.calledOnce
    expect(query).to.have.been.calledOnce
    expect(findAll).to.not.have.been.called
    expect(challenges.unionSqlInjectionChallenge.solved).to.equal(false)
    expect(challenges.dbSchemaChallenge.solved).to.equal(false)
  })

  it('loads only email and password of users when results contain an MD5 hash', async () => {
    productsQuery([{ id: 1, name: users[0].email, description: users[0].password }])

    searchProducts()(req, res, next)
    await flush()

    expect(findAll).to.have.been.calledOnceWith({ attributes: ['email', 'password'] })
    expect(challenges.unionSqlInjectionChallenge.solved).to.equal(false)
  })

  it('solves "unionSqlInjectionChallenge" when results contain all user credentials', async () => {
    productsQuery(users.map((user, i) => ({ id: i, name: user.email, description: user.password })))

    searchProducts()(req, res, next)
    await flush()

    expect(challenges.unionSqlInjectionChallenge.solved).to.equal(true)
    expect(query).to.not.have.been.calledWith('SELECT sql FROM sqlite_master')
  })

  it('solves "dbSchemaChallenge" when results contain all table definitions', async () => {
    productsQuery(tableDefinitions.map((table, i) => ({ id: table.sql, name: String(i) })))

    searchProducts()(req, res, next)
    await flush()

    expect(query).to.have.been.calledWith('SELECT sql FROM sqlite_master')
    expect(challenges.dbSchemaChallenge.solved).to.equal(true)
    expect(findAll).to.not.have.been.called
  })

  it('does not solve "dbSchemaChallenge" when only some table definitions are returned', async () => {
    productsQuery([{ id: tableDefinitions[2].sql, name: '1' }])

    searchProducts()(req, res, next)
    await flush()

    expect(query).to.have.been.calledWith('SELECT sql FROM sqlite_master')
    expect(challenges.dbSchemaChallenge.solved).to.equal(false)
  })

  it('skips both checks once the challenges are solved', async () => {
    challenges.unionSqlInjectionChallenge.solved = true
    challenges.dbSchemaChallenge.solved = true
    productsQuery([{ id: tableDefinitions[0].sql, name: users[0].email, description: users[0].password }])

    searchProducts()(req, res, next)
    await flush()

    expect(query).to.have.been.calledOnce
    expect(findAll).to.not.have.been.called
  })
})
