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

    it('should keep formatting but strip scripts from the feedback comment', () => {
        component.feedback = 'Nice<br><em>Support Team</em><img src=x onerror=alert(1)><iframe src="javascript:alert(1)"></iframe>'
        fixture.detectChanges()
        const cite: HTMLElement = fixture.nativeElement.querySelector('cite')
        expect(cite.querySelector('em')?.textContent).toBe('Support Team')
        expect(cite.querySelector('br')).not.toBeNull()
        expect(cite.querySelector('img')?.getAttribute('onerror')).toBeNull()
        expect(cite.querySelector('iframe')).toBeNull()
    })
})
