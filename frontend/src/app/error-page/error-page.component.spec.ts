/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { MatCardModule } from '@angular/material/card'

import { ErrorPageComponent } from './error-page.component'
import { ActivatedRoute } from '@angular/router'
import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { EventEmitter } from '@angular/core'
import { of, throwError } from 'rxjs'

describe('ErrorPageComponent', () => {
    let component: ErrorPageComponent
    let fixture: ComponentFixture<ErrorPageComponent>
    let translateService: any

    const createComponent = async (queryParams: Record<string, string>) => {
        await TestBed.configureTestingModule({
            imports: [
                TranslateModule.forRoot(),
                MatCardModule,
                ErrorPageComponent
            ],
            providers: [
                {
                    provide: ActivatedRoute,
                    useValue: { snapshot: { queryParams } }
                },
                { provide: TranslateService, useValue: translateService }
            ]
        })
            .compileComponents()

        fixture = TestBed.createComponent(ErrorPageComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    }

    beforeEach(() => {
        TestBed.resetTestingModule()
        translateService = {
            get: vi.fn().mockName('TranslateService.get')
        }
        translateService.get.mockReturnValue(of('Translated message'))
        translateService.onLangChange = new EventEmitter()
        translateService.onTranslationChange = new EventEmitter()
        translateService.onFallbackLangChange = new EventEmitter()
        translateService.onDefaultLangChange = new EventEmitter()
    })

    it('should create', async () => {
        await createComponent({ error: 'UNAUTHORIZED_PAGE_ACCESS_ERROR' })
        expect(component).toBeTruthy()
    })

    it('should show the translated message for the error query parameter', async () => {
        await createComponent({ error: 'UNAUTHORIZED_PAGE_ACCESS_ERROR' })
        expect(translateService.get).toHaveBeenCalledWith('UNAUTHORIZED_PAGE_ACCESS_ERROR')
        expect(component.error).toBe('Translated message')
    })

    it('should fall back to the translation id when translation fails', async () => {
        translateService.get.mockReturnValue(throwError(() => 'UNAUTHORIZED_PAGE_ACCESS_ERROR'))
        await createComponent({ error: 'UNAUTHORIZED_PAGE_ACCESS_ERROR' })
        expect(component.error).toBe('UNAUTHORIZED_PAGE_ACCESS_ERROR')
    })

    it('should not resolve any message when no error query parameter is given', async () => {
        await createComponent({})
        expect(translateService.get).not.toHaveBeenCalled()
        expect(component.error).toBeNull()
    })
})
