/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import {
  Model,
  type CreationOptional,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type Sequelize
} from 'sequelize'

class Captcha extends Model<
InferAttributes<Captcha>,
InferCreationAttributes<Captcha>
> {
  declare captchaId: string
  declare captcha: string
  declare answer: string
  declare createdAt: CreationOptional<Date>
}

const CaptchaModelInit = (sequelize: Sequelize) => {
  Captcha.init(
    {
      captchaId: {
        type: DataTypes.STRING,
        unique: true
      },
      captcha: DataTypes.STRING,
      answer: DataTypes.STRING,
      createdAt: DataTypes.DATE
    },
    {
      tableName: 'Captchas',
      sequelize
    }
  )
}

export { Captcha as CaptchaModel, CaptchaModelInit }
