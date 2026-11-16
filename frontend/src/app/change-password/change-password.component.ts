/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import {
  type AbstractControl,
  UntypedFormControl,
  Validators,
  FormsModule,
  ReactiveFormsModule
} from '@angular/forms'
import { UserService } from '../Services/user.service'
import { CookieService } from 'ngy-cookie'
import { Component, inject, OnInit } from '@angular/core'
import { library } from '@fortawesome/fontawesome-svg-core'
import { faSave } from '@fortawesome/free-solid-svg-icons'
import { faEdit } from '@fortawesome/free-regular-svg-icons'
import { FormSubmitService } from '../Services/form-submit.service'
import { TranslateService, TranslateModule } from '@ngx-translate/core'
import { MatButtonModule } from '@angular/material/button'

import { MatInputModule } from '@angular/material/input'
import {
  MatFormFieldModule,
  MatLabel,
  MatError,
  MatHint
} from '@angular/material/form-field'
import { MatCardModule } from '@angular/material/card'

library.add(faSave, faEdit)

@Component({
  selector: 'app-change-password',
  templateUrl: './change-password.component.html',
  styleUrls: ['./change-password.component.scss'],
  imports: [
    MatCardModule,
    TranslateModule,
    MatFormFieldModule,
    MatLabel,
    MatInputModule,
    FormsModule,
    ReactiveFormsModule,
    MatError,
    MatHint,
    MatButtonModule
  ]
})
export class ChangePasswordComponent implements OnInit {
  private readonly userService = inject(UserService)
  private readonly formSubmitService = inject(FormSubmitService)
  private readonly translate = inject(TranslateService)
  private readonly cookieService = inject(CookieService)

  public passwordControl: UntypedFormControl = new UntypedFormControl('', [
    Validators.required
  ])

  public newPasswordControl: UntypedFormControl = new UntypedFormControl('', [
    Validators.required,
    Validators.minLength(5),
    Validators.maxLength(40)
  ])

  public repeatNewPasswordControl: UntypedFormControl = new UntypedFormControl(
    '',
    [
      Validators.required,
      Validators.minLength(5),
      Validators.maxLength(40),
      matchValidator(this.newPasswordControl)
    ]
  )

  public error: any
  public confirmation: any
  public rotationToken: string | null = this.userService.passwordRotationToken
  public passwordLength = '5-40'

  ngOnInit (): void {
    if (this.rotationToken) {
      this.passwordControl.clearValidators()
      this.passwordControl.updateValueAndValidity()
      this.passwordLength = '12-40'
      this.newPasswordControl.setValidators([Validators.required, Validators.minLength(12), Validators.maxLength(40)])
      this.newPasswordControl.updateValueAndValidity()
    }
    this.formSubmitService.attachEnterKeyHandler(
      'password-form',
      'changeButton',
      () => {
        this.changePassword()
      }
    )
  }

  changePassword () {
    if (
      localStorage.getItem('email')?.match(/support@.*/) &&
      !this.newPasswordControl.value.match(
        /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,30}/
      )
    ) {
      console.error(
        'Parola echipei de asistență nu respectă politica corporativă pentru conturile privilegiate! Vă rugăm să schimbați parola în consecință!'
      )
    }
    const passwordChange = this.rotationToken
      ? this.userService.rotateInitialPassword({
        tmpToken: this.rotationToken,
        new: this.newPasswordControl.value,
        repeat: this.repeatNewPasswordControl.value
      })
      : this.userService.changePassword({
        current: this.passwordControl.value,
        new: this.newPasswordControl.value,
        repeat: this.repeatNewPasswordControl.value
      })
    passwordChange
      .subscribe({
        next: (authentication: any) => {
          if (this.rotationToken) {
            this.userService.passwordRotationToken = null
            this.rotationToken = null
            this.storeSession(authentication)
            this.passwordControl.setValidators([Validators.required])
            this.passwordControl.updateValueAndValidity()
          }
          this.error = undefined
          this.translate.get('PASSWORD_SUCCESSFULLY_CHANGED').subscribe({
            next: (passwordSuccessfullyChanged) => {
              this.confirmation = passwordSuccessfullyChanged
            },
            error: (translationId) => {
              this.confirmation = { error: translationId }
            }
          })
          this.resetForm()
        },
        error: (error) => {
          console.log(error)
          this.error = error
          this.confirmation = undefined
          this.resetPasswords()
        }
      })
  }

  storeSession (authentication: { token: string, bid: number }) {
    localStorage.setItem('token', authentication.token)
    const expires = new Date()
    expires.setHours(expires.getHours() + 8)
    this.cookieService.put('token', authentication.token, { expires })
    sessionStorage.setItem('bid', authentication.bid?.toString())
    this.userService.isLoggedIn.next(true)
  }

  resetForm () {
    this.passwordControl.setValue('')
    this.resetPasswords()
  }

  resetPasswords () {
    this.passwordControl.markAsPristine()
    this.passwordControl.markAsUntouched()
    this.newPasswordControl.setValue('')
    this.newPasswordControl.markAsPristine()
    this.newPasswordControl.markAsUntouched()
    this.repeatNewPasswordControl.setValue('')
    this.repeatNewPasswordControl.markAsPristine()
    this.repeatNewPasswordControl.markAsUntouched()
  }
}

function matchValidator (newPasswordControl: AbstractControl) {
  return function matchOtherValidate (
    repeatNewPasswordControl: UntypedFormControl
  ) {
    const password = newPasswordControl.value
    const passwordRepeat = repeatNewPasswordControl.value
    if (password !== passwordRepeat) {
      return { notSame: true }
    }
    return null
  }
}
