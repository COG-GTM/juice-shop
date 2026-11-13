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

class OAuthIdentity extends Model<
InferAttributes<OAuthIdentity>,
InferCreationAttributes<OAuthIdentity>
> {
  declare id: CreationOptional<number>
  declare UserId: number
  declare provider: CreationOptional<string>
}

const OAuthIdentityModelInit = (sequelize: Sequelize) => {
  OAuthIdentity.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      UserId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        unique: true
      },
      provider: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: 'google'
      }
    },
    {
      tableName: 'OAuthIdentities',
      sequelize
    }
  )
}

export { OAuthIdentity as OAuthIdentityModel, OAuthIdentityModelInit }
