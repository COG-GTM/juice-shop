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

      cy.window().then(async () => {
        const response = await fetch(`${Cypress.config('baseUrl')}/rest/user/data-export`, {
          method: 'POST',
          headers: {
            'Content-type': 'application/json',
            Authorization: `Bearer ${localStorage.getItem('token')}`
          },
          body: JSON.stringify({ format: '1' })
        })
        const body = await response.json()
        expect(response.status).to.equal(200)
        expect(JSON.parse(body.userData).orders).to.deep.equal([])
      })
    })
  })
})
