describe('/#/deluxe-membership', () => {
  describe('challenge "svgInjection"', () => {
    it('should not be possible to abuse the redirect-endpoint to load an external image', () => {
      cy.request({
        url: '/redirect?to=https://placecats.com/g/200/100?x=https://github.com/juice-shop/juice-shop',
        followRedirect: false,
        failOnStatusCode: false
      }).its('status').should('eq', 406)
    })
  })

  describe('challenge "freeDeluxe"', () => {
    it('should upgrade to deluxe for free by making a post request to /rest/deluxe-membership by setting the paymentMode parameter to null', () => {
      cy.login({
        email: 'jim',
        password: 'ncc-1701'
      })
      cy.visit('/#/')
      cy.getCookie('token').then((token) => {
        cy.request({
          url: '/rest/deluxe-membership',
          method: 'POST',
          headers: { Authorization: `Bearer ${token?.value}` }
        }).then((response) => {
          expect(response.body.status).contains('success')
        })
      })
      cy.expectChallengeSolved({ challenge: 'Deluxe Fraud' })
    })
  })
})
