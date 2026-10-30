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

    it('should not leak admin orders by causing email clash during export', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then((appDomain: string) => {
        cy.request('POST', '/rest/user/login', { email: `admun@${appDomain}`, password: 'admun123' }).then((login) => {
          cy.request({
            method: 'POST',
            url: '/rest/user/data-export',
            headers: { Authorization: `Bearer ${login.body.authentication.token}` },
            body: { format: '1' }
          }).then((response) => {
            expect(JSON.parse(response.body.userData).orders).to.deep.equal([])
          })
        })
      })
    })
  })
})
