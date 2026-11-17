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

class PasswordResetToken extends Model<
InferAttributes<PasswordResetToken>,
InferCreationAttributes<PasswordResetToken>
> {
  declare id: CreationOptional<number>
  declare UserId: number
  declare tokenHash: string
  declare expiresAt: Date
  declare usedAt: CreationOptional<Date | null>
}

const PasswordResetTokenModelInit = (sequelize: Sequelize) => {
  PasswordResetToken.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      UserId: {
        type: DataTypes.INTEGER,
        allowNull: false
      },
      tokenHash: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false
      },
      usedAt: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: null
      }
    },
    {
      tableName: 'PasswordResetTokens',
      sequelize
    }
  )
}

export { PasswordResetToken as PasswordResetTokenModel, PasswordResetTokenModelInit }
