/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'

class Captcha extends Model<
InferAttributes<Captcha>,
InferCreationAttributes<Captcha>
> {
  declare captchaId: number
  declare captcha: string
  declare answer: string
  declare createdAt: CreationOptional<Date>
}

const CaptchaModelInit = (sequelize: Sequelize) => {
  Captcha.init(
    {
      captchaId: {
        type: DataTypes.INTEGER
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
