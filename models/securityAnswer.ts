/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize,
  type BulkCreateOptions,
  type UpdateOptions
} from 'sequelize'
import * as security from '../lib/insecurity'

class SecurityAnswer extends Model<
InferAttributes<SecurityAnswer>,
InferCreationAttributes<SecurityAnswer>
> {
  declare SecurityQuestionId: number
  declare UserId: number
  declare id: CreationOptional<number>
  declare answer: string
}

const SecurityAnswerModelInit = (sequelize: Sequelize) => {
  SecurityAnswer.init(
    {
      UserId: {
        type: DataTypes.INTEGER,
        unique: true
      },
      SecurityQuestionId: {
        type: DataTypes.INTEGER
      },

      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      answer: {
        type: DataTypes.STRING
      }
    },
    {
      tableName: 'SecurityAnswers',
      sequelize
    }
  )

  const hashAnswer = async (securityAnswer: SecurityAnswer, options?: object) => {
    const prehashed = (options as { prehashed?: boolean } | undefined)?.prehashed === true
    if (!prehashed && securityAnswer.changed('answer') && securityAnswer.answer != null) {
      securityAnswer.answer = await security.hashSecurityAnswer(String(securityAnswer.answer))
    }
  }

  SecurityAnswer.addHook('beforeSave', hashAnswer)
  SecurityAnswer.addHook('beforeBulkCreate', async (securityAnswers: SecurityAnswer[], options: BulkCreateOptions<InferAttributes<SecurityAnswer>>) => {
    if (options.individualHooks === true) return
    await Promise.all(securityAnswers.map(async (securityAnswer) => { await hashAnswer(securityAnswer, options) }))
  })
  SecurityAnswer.addHook('beforeBulkUpdate', async (options: UpdateOptions<InferAttributes<SecurityAnswer>>) => {
    const { attributes } = options as unknown as { attributes?: { answer?: unknown } }
    if (options.individualHooks !== true && attributes?.answer != null) {
      attributes.answer = await security.hashSecurityAnswer(String(attributes.answer))
    }
  })
}

export { SecurityAnswer as SecurityAnswerModel, SecurityAnswerModelInit }
