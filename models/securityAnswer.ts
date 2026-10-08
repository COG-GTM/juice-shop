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
  type Sequelize
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

  SecurityAnswer.addHook('beforeSave', async (securityAnswer: SecurityAnswer) => {
    if ((securityAnswer.isNewRecord || securityAnswer.changed('answer')) && securityAnswer.getDataValue('answer') != null) {
      securityAnswer.setDataValue('answer', await security.hashSecurityAnswer(securityAnswer.getDataValue('answer')))
    }
  })
}

export { SecurityAnswer as SecurityAnswerModel, SecurityAnswerModelInit }
