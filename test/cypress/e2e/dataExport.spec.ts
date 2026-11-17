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

      cy.visit('/#/privacy-security/data-export')
      cy.get('#formatControl').contains('JSON').click()
      cy.get('#submitButton').click()
      cy.wait(2000)
      cy.request('/api/Challenges/?name=GDPR Data Theft').then((response) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        expect(response.body.data[0].solved).to.be.false
      })
    })
  })
})
