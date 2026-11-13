/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { Sequelize } from 'sequelize'
import { SecurityAnswerModel, SecurityAnswerModelInit } from '../../models/securityAnswer'
import * as security from '../../lib/insecurity'
const expect = chai.expect

describe('SecurityAnswerModel', () => {
  before(async () => {
    const sequelize = new Sequelize({ dialect: 'sqlite', storage: ':memory:', logging: false })
    SecurityAnswerModelInit(sequelize)
    await sequelize.sync()
  })

  beforeEach(async () => {
    await SecurityAnswerModel.destroy({ where: {}, truncate: true })
  })

  const storedAnswerOf = async (UserId: number) => (await SecurityAnswerModel.findOne({ where: { UserId } }))!.answer

  it('hashes answers on create', async () => {
    await SecurityAnswerModel.create({ UserId: 1, SecurityQuestionId: 1, answer: 'Samuel' })
    const stored = await storedAnswerOf(1)
    expect(stored).to.not.equal('Samuel')
    expect(await security.verifySecurityAnswer('Samuel', stored)).to.equal(true)
  })

  for (const individualHooks of [false, true]) {
    it(`hashes each answer exactly once on bulkCreate with individualHooks=${individualHooks}`, async () => {
      await SecurityAnswerModel.bulkCreate([
        { UserId: 1, SecurityQuestionId: 1, answer: 'Samuel' },
        { UserId: 2, SecurityQuestionId: 2, answer: 'Rex' }
      ], { individualHooks })
      expect(await security.verifySecurityAnswer('Samuel', await storedAnswerOf(1))).to.equal(true)
      expect(await security.verifySecurityAnswer('Rex', await storedAnswerOf(2))).to.equal(true)
    })

    it(`hashes the new answer exactly once on bulk update with individualHooks=${individualHooks}`, async () => {
      await SecurityAnswerModel.create({ UserId: 1, SecurityQuestionId: 1, answer: 'Samuel' })
      await SecurityAnswerModel.update({ answer: 'Fluffy' }, { where: { UserId: 1 }, individualHooks })
      const stored = await storedAnswerOf(1)
      expect(await security.verifySecurityAnswer('Fluffy', stored)).to.equal(true)
      expect(await security.verifySecurityAnswer('Samuel', stored)).to.equal(false)
    })
  }

  it('does not re-hash an unchanged answer when other fields are saved', async () => {
    const answer = await SecurityAnswerModel.create({ UserId: 1, SecurityQuestionId: 1, answer: 'Samuel' })
    answer.SecurityQuestionId = 2
    await answer.save()
    expect(await security.verifySecurityAnswer('Samuel', await storedAnswerOf(1))).to.equal(true)
  })
})
