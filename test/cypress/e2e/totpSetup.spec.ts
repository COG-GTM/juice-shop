describe('/#/basket', () => {
  describe('as amy', () => {
    beforeEach(() => {
      cy.login({
        email: 'amy',
        password: 'K1f.....................'
      })
    })

    it('should be possible to setup 2fa for a account without 2fa enabled', async () => {
      cy.visit('/#/privacy-security/two-factor-authentication')

      cy.get('#initialToken')
        .should('have.attr', 'data-test-totp-secret')
        .then(($val) => {
          // console.log($val);
          cy.get('#currentPasswordSetup').type('K1f.....................')

          cy.task<string>('GenerateAuthenticator', $val).then((secret: string) => {
            cy.get('#initialToken').type(secret)
            cy.get('#setupTwoFactorAuth').click()

            cy.get('#currentPasswordDisable').type('K1f.....................')
            cy.get('#disableTwoFactorAuth').click()
          })
        })
      cy.get('.mat-snack-bar-container').should(
        'contain',
        'Two-Factor Authentication has been removed.'
      )
    })
  })
})
