/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export type TrackedTable = 'Feedbacks' | 'Complaints' | 'Products'
export type TableChanges = Record<TrackedTable, boolean>

const changed: TableChanges = { Feedbacks: true, Complaints: true, Products: true }

export function markChanged (table: TrackedTable) {
  changed[table] = true
}

export function consumeChanges (): TableChanges {
  const changes = { ...changed }
  changed.Feedbacks = false
  changed.Complaints = false
  changed.Products = false
  return changes
}

export function changeTrackingHooks (table: TrackedTable) {
  const mark = () => { markChanged(table) }
  return {
    afterCreate: mark,
    afterBulkCreate: mark,
    afterUpdate: mark,
    afterBulkUpdate: mark,
    afterUpsert: mark,
    afterDestroy: mark,
    afterBulkDestroy: mark,
    afterRestore: mark,
    afterBulkRestore: mark
  }
}
