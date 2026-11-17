/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// @ts-expect-error FIXME due to non-existing type definitions for MarsDB
import * as MarsDB from 'marsdb'

// MarsDB compiles $where selectors into executable code (SNYK-JS-MARSDB-480405)
export function containsWhereOperator (selector: unknown): boolean {
  if (typeof selector === 'function') return true
  if (selector === null || typeof selector !== 'object') return false
  if (Array.isArray(selector)) return selector.some(containsWhereOperator)
  return Object.keys(selector).some(key => key === '$where' || containsWhereOperator((selector as Record<string, unknown>)[key]))
}

function withSafeSelectors (collection: any) {
  for (const method of ['find', 'findOne', 'update', 'remove', 'count', 'ids']) {
    const original = collection[method].bind(collection)
    collection[method] = (selector: unknown, ...args: unknown[]) => {
      if (containsWhereOperator(selector)) {
        return Promise.reject(new Error('Unsupported query operator: $where'))
      }
      return original(selector, ...args)
    }
  }
  return collection
}

export const reviewsCollection = withSafeSelectors(new MarsDB.Collection('posts'))
export const ordersCollection = withSafeSelectors(new MarsDB.Collection('orders'))
