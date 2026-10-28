describe('/ftp', () => {
  describe('non-public files', () => {
    for (const path of [
      '/ftp/acquisitions.md',
      '/ftp/incident-support.kdbx',
      '/ftp/coupons_2013.md.bak%2500.md',
      '/ftp/package.json.bak%2500.md',
      '/ftp/eastere.gg%2500.md',
      '/ftp/suspicious_errors.yml%2500.md',
      '/ftp/encrypt.pyc%2500.md'
    ]) {
      it(`should not be able to access ${path}`, () => {
        cy.request({ url: path, failOnStatusCode: false }).its('status').should('eq', 404)
      })
    }
  })

  describe('challenge "errorHandling"', () => {
    it('should leak information through error message accessing /ftp/easter.egg', () => {
      cy.visit('/ftp/easter.egg', { failOnStatusCode: false })

      cy.get('#stacktrace').then((elements) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        expect(!!elements.length).to.be.true
      })
      cy.expectChallengeSolved({ challenge: 'Error Handling' })
    })
  })
})
