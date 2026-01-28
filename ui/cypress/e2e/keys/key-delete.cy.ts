/// <reference types="cypress" />

describe('Delete Key', () => {
  let testKeyId: string

  beforeEach(() => {
    cy.setupAuth()

    // Intercept the key detail API call
    cy.intercept('GET', '**/api/hsm/keys/*').as('getKey')

    // Create a test key for deletion testing
    cy.createKeyViaApi({ algorithm: 'ED25519', purpose: 'SIGN' }).then((key) => {
      testKeyId = key.key_id
    })
  })

  afterEach(() => {
    // Cleanup in case test didn't delete the key
    if (testKeyId) {
      cy.deleteKeyViaApi(testKeyId).then(() => {
        // Reset for next test
      })
    }
  })

  describe('Delete Confirmation Dialog', () => {
    beforeEach(() => {
      // Navigate to key detail page for delete
      cy.visit(`/keys/${testKeyId}`)
      // Wait for key detail API to complete
      cy.wait('@getKey')
      cy.contains('Key Details', { timeout: 10000 }).should('be.visible')
      // Click delete button in header
      cy.contains('button', /delete/i).click()
    })

    it('displays confirmation dialog', () => {
      cy.get('[role="dialog"]').should('be.visible')
    })

    it('shows warning message', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.contains(/cannot be undone/i).should('be.visible')
      })
    })

    it('shows key ID in confirmation', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.contains(testKeyId.substring(0, 8)).should('be.visible')
      })
    })

    it('requires typing DELETE to confirm', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.get('input#confirmation[placeholder="DELETE"]').should('exist')
      })
    })

    it('delete button is disabled until DELETE is typed', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /delete key/i).should('be.disabled')
      })
    })

    it('enables delete button after typing DELETE', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.get('input#confirmation').type('DELETE')

        cy.contains('button', /delete key/i).should('not.be.disabled')
      })
    })
  })

  describe('Successful Deletion', () => {
    it('deletes key when confirmed', () => {
      cy.visit(`/keys/${testKeyId}`)
      cy.wait('@getKey')
      cy.contains('Key Details', { timeout: 10000 }).should('be.visible')
      cy.contains('button', /delete/i).click()

      cy.get('[role="dialog"]').within(() => {
        cy.get('input#confirmation').type('DELETE')
        cy.contains('button', /delete key/i).click()
      })

      // Should redirect to keys list
      cy.url().should('include', '/keys')
      cy.url().should('not.include', testKeyId)

      // Mark as deleted so afterEach doesn't try to delete again
      testKeyId = ''
    })

    it('shows success message after deletion', () => {
      cy.visit(`/keys/${testKeyId}`)
      cy.wait('@getKey')
      cy.contains('Key Details', { timeout: 10000 }).should('be.visible')
      cy.contains('button', /delete/i).click()

      cy.get('[role="dialog"]').within(() => {
        cy.get('input#confirmation').type('DELETE')
        cy.contains('button', /delete key/i).click()
      })

      // Should show success toast/message
      cy.contains(/deleted/i).should('be.visible')

      testKeyId = ''
    })
  })

  describe('Cancel Deletion', () => {
    beforeEach(() => {
      cy.visit(`/keys/${testKeyId}`)
      cy.wait('@getKey')
      cy.contains('Key Details', { timeout: 10000 }).should('be.visible')
      cy.contains('button', /delete/i).click()
    })

    it('cancels deletion when clicking cancel', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /cancel/i).click()
      })

      cy.get('[role="dialog"]').should('not.exist')

      // Key should still exist
      cy.url().should('include', testKeyId)
    })

    it('cancels deletion when pressing Escape', () => {
      cy.get('body').type('{esc}')

      cy.get('[role="dialog"]').should('not.exist')
    })

    it('key remains accessible after cancellation', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /cancel/i).click()
      })

      // Should still be on detail page
      cy.contains('Key Details').should('be.visible')
    })
  })
})
