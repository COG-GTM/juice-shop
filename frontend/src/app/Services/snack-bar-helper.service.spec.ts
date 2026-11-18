/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TestBed } from '@angular/core/testing'
import { TranslateNoOpLoader, provideTranslateService, provideTranslateLoader, TranslateService } from '@ngx-translate/core'
import { MatSnackBarModule } from '@angular/material/snack-bar'

import { SnackBarHelperService } from './snack-bar-helper.service'

describe('SnackBarHelperService', () => {
    beforeEach(() => TestBed.configureTestingModule({
        imports: [
            MatSnackBarModule
        ],
        providers: [provideTranslateService({ loader: provideTranslateLoader(TranslateNoOpLoader) }), TranslateService]
    }))

    it('should be created', () => {
        const service: SnackBarHelperService = TestBed.inject(SnackBarHelperService)
        expect(service).toBeTruthy()
    })
})
