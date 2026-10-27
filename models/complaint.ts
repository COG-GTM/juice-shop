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
import { changeTrackingHooks } from '../lib/tableChanges'

class Complaint extends Model<
InferAttributes<Complaint>,
InferCreationAttributes<Complaint>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare message: string
  declare file: CreationOptional<string>
}

const ComplaintModelInit = (sequelize: Sequelize) => {
  Complaint.init(
    {
      UserId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      message: DataTypes.STRING,
      file: DataTypes.STRING
    },
    {
      tableName: 'Complaints',
      sequelize,
      hooks: changeTrackingHooks('Complaints')
    }
  )
}

export { Complaint as ComplaintModel, ComplaintModelInit }
