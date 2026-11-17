/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// @ts-expect-error FIXME due to non-existing type definitions for MarsDB
import * as MarsDB from 'marsdb'

// MarsDB compiles `$where` selectors into a Function (SNYK-JS-MARSDB-480405, no upstream fix)
export function containsCodeSelector (selector: unknown, depth = 0): boolean {
  if (typeof selector === 'function') return true
  if (selector === null || typeof selector !== 'object') return false
  if (depth > 32) return true
  return Object.entries(selector).some(([key, value]) => key === '$where' || containsCodeSelector(value, depth + 1))
}

const selectorMethods = ['find', 'findOne', 'count', 'ids', 'update', 'remove']

function withoutCodeSelectors (collection: any) {
  for (const method of selectorMethods) {
    const original = collection[method].bind(collection)
    collection[method] = (selector: unknown, ...args: unknown[]) => {
      if (containsCodeSelector(selector)) {
        return Promise.reject(new Error('JavaScript selectors ($where) are not allowed'))
      }
      return original(selector, ...args)
    }
  }
  return collection
}

export const reviewsCollection = withoutCodeSelectors(new MarsDB.Collection('posts'))
export const ordersCollection = withoutCodeSelectors(new MarsDB.Collection('orders'))
