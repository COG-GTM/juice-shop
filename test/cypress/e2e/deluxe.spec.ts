describe('/#/deluxe-membership', () => {
  describe('challenge "svgInjection"', () => {
    it('should be possible to pass in a forgotten test parameter abusing the redirect-endpoint to load an external image', () => {
      cy.login({ email: 'jim', password: 'ncc-1701' })
      cy.location().then((loc) => {
        cy.visit(
          `/#/deluxe-membership?testDecal=${encodeURIComponent(
            `../../..${loc.pathname}/redirect?to=https://placecats.com/g/200/100?x=https://github.com/juice-shop/juice-shop`
          )}`
        )
      })

      cy.expectChallengeSolved({ challenge: 'Cross-Site Imaging' })
    })
  })

  describe('payment enforcement', () => {
    it('should not upgrade to deluxe when no paymentMode is given', () => {
      cy.login({
        email: 'jim',
        password: 'ncc-1701'
      })
      cy.visit('/#/')
      cy.getCookie('token').then((token) => {
        cy.request({
          url: '/rest/deluxe-membership',
          method: 'POST',
          headers: { Authorization: `Bearer ${token?.value}` },
          failOnStatusCode: false
        }).then((response) => {
          expect(response.status).to.equal(400)
          expect(response.body.error).to.equal('Invalid payment mode')
        })
      })
    })
  })
})
