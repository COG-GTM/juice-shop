describe('/#/privacy-security/data-export', () => {
  describe('challenge "dataExportChallenge"', () => {
    beforeEach(() => {
      cy.visit('/#/register')

      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#emailControl').type(`admun@${appDomain}`)
        }
      )
      cy.get('#passwordControl').focus().type('admun123')
      cy.get('#repeatPasswordControl').focus().type('admun123')

      cy.get('mat-select[name="securityQuestion"]').focus().click({ force: true })
      cy.get('.mat-mdc-option')
        .contains('Your eldest siblings middle name?')
        .click()

      cy.get('#securityAnswerControl').focus().type('admun')
      cy.get('#registerButton').click()
    })

    it('should not be possible to steal admin user data by causing email clash during export', () => {
      cy.login({ email: 'admun', password: 'admun123' })

      cy.intercept('POST', '/rest/user/data-export').as('dataExport')
      cy.visit('/#/privacy-security/data-export')
      cy.get('#formatControl').contains('JSON').click()
      cy.get('#submitButton').click()
      cy.wait('@dataExport').then(({ response }) => {
        expect(JSON.parse(response?.body.userData).orders).to.have.length(0)
      })
    })
  })
})
