/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import config from 'config'
import {
  type InferAttributes,
  type InferCreationAttributes,
  Model,
  DataTypes,
  type CreationOptional,
  type Sequelize,
  type BulkCreateOptions,
  type UpdateOptions
} from 'sequelize'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

class User extends Model<
InferAttributes<User>,
InferCreationAttributes<User>
> {
  declare id: CreationOptional<number>
  declare username: string | undefined
  declare email: CreationOptional<string>
  declare password: CreationOptional<string>
  declare role: CreationOptional<string>
  declare deluxeToken: CreationOptional<string>
  declare lastLoginIp: CreationOptional<string>
  declare profileImage: CreationOptional<string>
  declare totpSecret: CreationOptional<string>
  declare isActive: CreationOptional<boolean>
}

const UserModelInit = (sequelize: Sequelize) => { // vuln-code-snippet start weakPasswordChallenge
  User.init(
    { // vuln-code-snippet hide-start
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      username: {
        type: DataTypes.STRING,
        defaultValue: '',
        set (username: string) {
          if (utils.isChallengeEnabled(challenges.persistedXssUserChallenge)) {
            username = security.sanitizeLegacy(username)
          } else {
            username = security.sanitizeSecure(username)
          }
          this.setDataValue('username', username)
        }
      },
      email: {
        type: DataTypes.STRING,
        unique: true,
        set (email: string) {
          if (utils.isChallengeEnabled(challenges.persistedXssUserChallenge)) {
            challengeUtils.solveIf(challenges.persistedXssUserChallenge, () => {
              return utils.contains(
                email,
                '<iframe src="javascript:alert(`xss`)">'
              )
            })
          } else {
            email = security.sanitizeSecure(email)
          }
          this.setDataValue('email', email)
        }
      }, // vuln-code-snippet hide-end
      password: {
        type: DataTypes.STRING,
        set (clearTextPassword: string) {
          this.setDataValue('password', clearTextPassword) // vuln-code-snippet vuln-line weakPasswordChallenge
        }
      }, // vuln-code-snippet end weakPasswordChallenge
      role: {
        type: DataTypes.STRING,
        defaultValue: 'customer',
        validate: {
          isIn: [['customer', 'deluxe', 'accounting', 'admin']]
        },
        set (role: string) {
          const profileImage = this.getDataValue('profileImage')
          if (
            role === security.roles.admin &&
          (!profileImage ||
            profileImage === '/assets/public/images/uploads/default.svg')
          ) {
            this.setDataValue(
              'profileImage',
              '/assets/public/images/uploads/defaultAdmin.png'
            )
          }
          this.setDataValue('role', role)
        }
      },
      deluxeToken: {
        type: DataTypes.STRING,
        defaultValue: ''
      },
      lastLoginIp: {
        type: DataTypes.STRING,
        defaultValue: '0.0.0.0'
      },
      profileImage: {
        type: DataTypes.STRING,
        defaultValue: '/assets/public/images/uploads/default.svg'
      },
      totpSecret: {
        type: DataTypes.STRING,
        defaultValue: ''
      },
      isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
      }
    },
    {
      tableName: 'Users',
      paranoid: true,
      defaultScope: {
        attributes: { exclude: ['password', 'totpSecret', 'deluxeToken'] }
      },
      scopes: {
        withSecrets: {}
      },
      sequelize
    }
  )

  const hashPassword = async (user: User, options?: object) => {
    const password = user.getDataValue('password')
    const prehashed = (options as { prehashed?: boolean } | undefined)?.prehashed === true
    if (!prehashed && user.changed('password') && password != null) {
      user.setDataValue('password', await security.hashPassword(String(password)))
    }
  }

  User.addHook('beforeCreate', hashPassword)
  User.addHook('beforeUpdate', hashPassword)
  User.addHook('beforeBulkCreate', async (users: User[], options: BulkCreateOptions<InferAttributes<User>>) => {
    if (options.individualHooks === true) return
    await Promise.all(users.map(async (user) => { await hashPassword(user, options) }))
  })
  User.addHook('beforeBulkUpdate', async (options: UpdateOptions<InferAttributes<User>>) => {
    const { attributes } = options as unknown as { attributes?: { password?: unknown } }
    if (options.individualHooks !== true && attributes?.password != null) {
      attributes.password = await security.hashPassword(String(attributes.password))
    }
  })

  User.addHook('afterValidate', async (user: User) => {
    if (
      user.email &&
    user.email.toLowerCase() ===
      `acc0unt4nt@${config.get<string>('application.domain')}`.toLowerCase()
    ) {
      await Promise.reject(
        new Error(
          'Nice try, but this is not how the "Ephemeral Accountant" challenge works!'
        )
      )
    }
  })
}

export { User as UserModel, UserModelInit }
