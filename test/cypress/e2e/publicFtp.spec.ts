describe('/ftp', () => {
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

  describe('restricted files', () => {
    for (const file of ['acquisitions.md', 'incident-support.kdbx', 'coupons_2013.md.bak%2500.md', 'package.json.bak%2500.md', 'eastere.gg%2500.md']) {
      it(`should not serve /ftp/${file}`, () => {
        cy.request({ url: `/ftp/${file}`, failOnStatusCode: false }).its('status').should('eq', 403)
      })
    }
  })
})
