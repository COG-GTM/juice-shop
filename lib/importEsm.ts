/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// The CommonJS build turns `import()` into `require()`, which cannot load ESM-only packages on Node < 22.12
// eslint-disable-next-line no-new-func
export const importEsm = new Function('specifier', 'return import(specifier)') as <T>(specifier: string) => Promise<T>
