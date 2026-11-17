describe('/#/forgot-password', () => {
  beforeEach(() => {
    cy.get('body').then(($body) => {
      if ($body.find('#logout').length) {
        cy.get('#logout').click()
      }
    })
  })

  it('should only offer requesting a reset link by email without a token', () => {
    cy.visit('/#/forgot-password')
    cy.get('#securityAnswer').should('not.exist')
    cy.get('#newPassword').should('not.exist')
    cy.task<string>('GetFromConfig', 'application.domain').then(
      (appDomain: string) => {
        cy.get('#email').type(`jim@${appDomain}`)
      }
    )
    cy.get('#requestResetButton').click()
    cy.get('.confirmation').should('not.be.hidden')
  })

  it('should reject an invalid reset token', () => {
    cy.visit('/#/forgot-password?token=invalid')
    cy.get('#newPassword').focus().type('I <3 Spock')
    cy.get('#newPasswordRepeat').focus().type('I <3 Spock')
    cy.get('#resetButton').click()
    cy.get('.error').should('contain.text', 'Invalid or expired password reset link.')
  })
})
