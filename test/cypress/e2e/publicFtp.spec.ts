describe('/ftp', () => {
  describe('confidential documents', () => {
    it('should not serve file /ftp/acquisitions.md', () => {
      cy.request({ url: '/ftp/acquisitions.md', failOnStatusCode: false }).its('status').should('equal', 404)
    })
  })

  describe('challenge "errorHandling"', () => {
    it('should leak information through error message accessing /ftp/easter.egg due to wrong file suffix', () => {
      cy.visit('/ftp/easter.egg', { failOnStatusCode: false })

      cy.get('#stacktrace').then((elements) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        expect(!!elements.length).to.be.true
      })
      cy.expectChallengeSolved({ challenge: 'Error Handling' })
    })
  })

  describe('poison null byte', () => {
    for (const file of ['coupons_2013.md.bak', 'package.json.bak', 'eastere.gg', 'suspicious_errors.yml', 'encrypt.pyc']) {
      it(`should not serve /ftp/${file} through a poison null byte attack`, () => {
        cy.request({ url: `/ftp/${file}%2500.md`, failOnStatusCode: false }).its('status').should('equal', 403)
      })
    }
  })
})
