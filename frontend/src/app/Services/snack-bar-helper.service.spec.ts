/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TestBed } from '@angular/core/testing'
import { TranslateNoOpLoader, TranslateLoader, TranslateModule, TranslateService } from '@ngx-translate/core'
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar'
import { of, throwError } from 'rxjs'

import { SnackBarHelperService } from './snack-bar-helper.service'

describe('SnackBarHelperService', () => {
    let snackBar: { open: ReturnType<typeof vi.fn> }
    let translateService: { get: ReturnType<typeof vi.fn> }

    beforeEach(() => {
        snackBar = { open: vi.fn() }
        translateService = { get: vi.fn() }

        TestBed.configureTestingModule({
            imports: [
                TranslateModule.forRoot({
                    loader: {
                        provide: TranslateLoader,
                        useClass: TranslateNoOpLoader
                    }
                }),
                MatSnackBarModule
            ],
            providers: [
                { provide: TranslateService, useValue: translateService },
                { provide: MatSnackBar, useValue: snackBar }
            ]
        })
    })

    it('should be created', () => {
        const service: SnackBarHelperService = TestBed.inject(SnackBarHelperService)
        expect(service).toBeTruthy()
    })

    it('should show the translated message', () => {
        translateService.get.mockReturnValue(of('translated message'))
        const service: SnackBarHelperService = TestBed.inject(SnackBarHelperService)

        service.open('MESSAGE_KEY', 'confirmBar')

        expect(translateService.get).toHaveBeenCalledWith('MESSAGE_KEY')
        expect(snackBar.open).toHaveBeenCalledWith('translated message', 'X', {
            duration: 5000,
            panelClass: ['confirmBar', 'mat-body']
        })
    })

    it('should fall back to the raw message when translation fails', () => {
        translateService.get.mockReturnValue(throwError(() => new Error('translation failed')))
        const service: SnackBarHelperService = TestBed.inject(SnackBarHelperService)

        service.open('MESSAGE_KEY', 'errorBar')

        expect(snackBar.open).toHaveBeenCalledWith('MESSAGE_KEY', 'X', {
            duration: 5000,
            panelClass: ['errorBar', 'mat-body']
        })
    })

    it('should keep an undefined css class in the panel classes', () => {
        translateService.get.mockReturnValue(of('translated message'))
        const service: SnackBarHelperService = TestBed.inject(SnackBarHelperService)

        service.open('MESSAGE_KEY')

        expect(snackBar.open).toHaveBeenCalledWith('translated message', 'X', {
            duration: 5000,
            panelClass: [undefined, 'mat-body']
        })
    })
})
