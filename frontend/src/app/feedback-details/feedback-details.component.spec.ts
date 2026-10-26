/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule } from '@ngx-translate/core'
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog'
import { UserService } from '../Services/user.service'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { MatDividerModule } from '@angular/material/divider'
import { type ComponentFixture, TestBed } from '@angular/core/testing'

import { FeedbackDetailsComponent } from './feedback-details.component'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('FeedbackDetailsComponent', () => {
    let component: FeedbackDetailsComponent
    let fixture: ComponentFixture<FeedbackDetailsComponent>

    beforeEach(async () => {
        TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(),
                MatDividerModule,
                MatDialogModule,
                FeedbackDetailsComponent],
            providers: [
                UserService,
                { provide: MatDialogRef, useValue: {} },
                { provide: MAT_DIALOG_DATA, useValue: { productData: {} } },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
            .compileComponents()
    })

    beforeEach(() => {
        fixture = TestBed.createComponent(FeedbackDetailsComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })
    it('should render safe formatting tags in feedback', () => {
        component.feedback = 'This is <b>the</b> store for awesome stuff of all kinds!'
        fixture.detectChanges()
        const cite: HTMLElement = fixture.nativeElement.querySelector('cite')
        expect(cite.querySelector('b')?.textContent).toBe('the')
        expect(cite.textContent).toBe('This is the store for awesome stuff of all kinds!')
    })

    it('should strip unsafe markup from feedback', () => {
        component.feedback = 'Hi <iframe src="javascript:alert(`xss`)"></iframe><img src="x" onerror="alert(1)">'
        fixture.detectChanges()
        const cite: HTMLElement = fixture.nativeElement.querySelector('cite')
        expect(cite.querySelector('iframe')).toBeNull()
        expect(cite.querySelector('img')?.hasAttribute('onerror')).toBeFalsy()
    })
})
