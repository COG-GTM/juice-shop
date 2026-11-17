/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule } from '@ngx-translate/core'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { ReactiveFormsModule } from '@angular/forms'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { ForgotPasswordComponent } from './forgot-password.component'

import { MatButtonModule } from '@angular/material/button'
import { MatInputModule } from '@angular/material/input'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MatCardModule } from '@angular/material/card'
import { UserService } from 'src/app/Services/user.service'
import { of, throwError } from 'rxjs'
import { MatTooltipModule } from '@angular/material/tooltip'
import { MatIconModule } from '@angular/material/icon'
import { MatSlideToggleModule } from '@angular/material/slide-toggle'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('ForgotPasswordComponent', () => {
    let component: ForgotPasswordComponent
    let fixture: ComponentFixture<ForgotPasswordComponent>
    let userService: any
    let queryParams: Record<string, string>

    async function createComponent () {
        TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(),
                ReactiveFormsModule,
                MatCardModule,
                MatFormFieldModule,
                MatInputModule,
                MatButtonModule,
                MatTooltipModule,
                MatIconModule,
                MatSlideToggleModule,
                ForgotPasswordComponent],
            providers: [
                { provide: UserService, useValue: userService },
                { provide: ActivatedRoute, useValue: { snapshot: { queryParamMap: convertToParamMap(queryParams) } } },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
        await TestBed.compileComponents()
        fixture = TestBed.createComponent(ForgotPasswordComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    }

    beforeEach(() => {
        userService = {
            requestPasswordReset: vi.fn().mockName('UserService.requestPasswordReset'),
            resetPassword: vi.fn().mockName('UserService.resetPassword')
        }
        userService.requestPasswordReset.mockReturnValue(of({ status: 'success' }))
        userService.resetPassword.mockReturnValue(of({}))
        queryParams = {}
    })

    describe('without reset token', () => {
        beforeEach(async () => { await createComponent() })

        it('should create', () => {
            expect(component).toBeTruthy()
            expect(component.resetToken).toBeNull()
        })

        it('should show the email form and no password form', () => {
            expect(fixture.nativeElement.querySelector('#email')).toBeTruthy()
            expect(fixture.nativeElement.querySelector('#requestResetButton')).toBeTruthy()
            expect(fixture.nativeElement.querySelector('#newPassword')).toBeNull()
            expect(fixture.nativeElement.querySelector('#securityAnswer')).toBeNull()
        })

        it('should be compulsory to fill the email field', () => {
            component.emailControl.setValue('')
            expect(component.emailControl.valid).toBeFalsy()
        })

        it('should hold a valid email in the email field', () => {
            component.emailControl.setValue('aa')
            expect(component.emailControl.valid).toBeFalsy()
            component.emailControl.setValue('a@a')
            expect(component.emailControl.valid).toBe(true)
        })

        it('should request a reset link and show confirmation', () => {
            vi.spyOn(component, 'resetForm')
            component.emailControl.setValue('a@a')
            component.requestResetLink()
            expect(userService.requestPasswordReset).toHaveBeenCalledWith({ email: 'a@a' })
            expect(component.confirmation).toBeDefined()
            expect(component.resetForm).toHaveBeenCalled()
        })

        it('should gracefully handle error on reset link request', () => {
            userService.requestPasswordReset.mockReturnValue(throwError({ error: 'Error' }))
            vi.spyOn(component, 'resetErrorForm')
            component.requestResetLink()
            expect(component.error).toBe('Error')
            expect(component.resetErrorForm).toHaveBeenCalled()
        })
    })

    describe('with reset token', () => {
        beforeEach(async () => {
            queryParams = { token: 'one-time-token' }
            await createComponent()
        })

        it('should read the reset token from the query parameters', () => {
            expect(component.resetToken).toBe('one-time-token')
        })

        it('should show the password form and no email form', () => {
            expect(fixture.nativeElement.querySelector('#newPassword')).toBeTruthy()
            expect(fixture.nativeElement.querySelector('#resetButton')).toBeTruthy()
            expect(fixture.nativeElement.querySelector('#email')).toBeNull()
        })

        it('should be compulsory to fill the password field', () => {
            component.passwordControl.setValue('')
            expect(component.passwordControl.valid).toBeFalsy()
        })

        it('should have a password length of at least five characters', () => {
            component.passwordControl.setValue('aaa')
            expect(component.passwordControl.valid).toBeFalsy()
            component.passwordControl.setValue('aaaaa')
            expect(component.passwordControl.valid).toBe(true)
        })

        it('should allow password length of more than twenty characters', () => {
            component.passwordControl.setValue('aaaaaaaaaaaaaaaaaaaaa')
            expect(component.passwordControl.valid).toBe(true)
        })

        it('should be compulsory to repeat the password', () => {
            component.passwordControl.setValue('a')
            component.repeatPasswordControl.setValue('')
            expect(component.repeatPasswordControl.valid).toBeFalsy()
            component.repeatPasswordControl.setValue('a')
            expect(component.repeatPasswordControl.valid).toBe(true)
        })

        it('should reset form on calling resetForm', () => {
            component.passwordControl.setValue('password')
            component.repeatPasswordControl.setValue('repeat password')
            component.resetForm()
            expect(component.passwordControl.pristine).toBe(true)
            expect(component.passwordControl.untouched).toBe(true)
            expect(component.passwordControl.value).toBe('')
            expect(component.repeatPasswordControl.pristine).toBe(true)
            expect(component.repeatPasswordControl.untouched).toBe(true)
            expect(component.repeatPasswordControl.value).toBe('')
        })

        it('should send the token with the new password and show confirmation', () => {
            vi.spyOn(component, 'resetForm')
            component.passwordControl.setValue('abcdef')
            component.repeatPasswordControl.setValue('abcdef')
            component.resetPassword()
            expect(userService.resetPassword).toHaveBeenCalledWith({ token: 'one-time-token', new: 'abcdef', repeat: 'abcdef' })
            expect(component.confirmation).toBeDefined()
            expect(component.resetForm).toHaveBeenCalled()
        })

        it('should clear form and gracefully handle error on password change', () => {
            userService.resetPassword.mockReturnValue(throwError({ error: 'Error' }))
            vi.spyOn(component, 'resetErrorForm')
            component.resetPassword()
            expect(component.error).toBe('Error')
            expect(component.resetErrorForm).toHaveBeenCalled()
        })
    })
})
