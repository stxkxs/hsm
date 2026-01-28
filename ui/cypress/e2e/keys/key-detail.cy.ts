/// <reference types="cypress" />

describe('Key Detail Page', () => {
  let testKeyId: string

  beforeEach(() => {
    cy.setupAuth()

    // Intercept the key detail API call
    cy.intercept('GET', '**/api/hsm/keys/*').as('getKey')

    // Create a test key
    cy.createKeyViaApi({ algorithm: 'ED25519', purpose: 'SIGN' }).then((key) => {
      testKeyId = key.key_id
      cy.visit(`/keys/${testKeyId}`)
      // Wait for API and page to load
      cy.wait('@getKey')
      cy.contains('Key Details', { timeout: 10000 }).should('be.visible')
    })
  })

  afterEach(() => {
    if (testKeyId) {
      cy.deleteKeyViaApi(testKeyId)
    }
  })

  describe('Page Display', () => {
    it('displays the key detail page', () => {
      cy.url().should('include', `/keys/${testKeyId}`)
    })

    it('displays the key ID', () => {
      cy.contains(testKeyId.substring(0, 8)).should('be.visible')
    })

    it('displays the algorithm', () => {
      cy.contains('Ed25519').should('be.visible')
    })

    it('displays the key status', () => {
      cy.contains(/Active/i).should('be.visible')
    })
  })

  describe('Public Key Display', () => {
    it('displays the public key section', () => {
      cy.contains(/public.*key/i).should('exist')
    })
  })

  describe('Key Metadata', () => {
    it('displays namespace', () => {
      cy.contains(/namespace/i).should('exist')
      cy.contains('default').should('exist')
    })
  })

  describe('Actions', () => {
    it('displays delete button in header', () => {
      // Delete button is in the header with Trash2 icon
      cy.contains('button', /delete/i).should('be.visible')
    })

    it('displays back navigation link', () => {
      cy.get('a[href="/keys"]').should('exist')
    })
  })

  describe('Navigation', () => {
    it('navigates back to key list', () => {
      cy.get('a[href="/keys"]').first().click()

      cy.url().should('include', '/keys')
      cy.url().should('not.include', testKeyId)
    })

    it('navigates back using browser back button', () => {
      // Intercept the keys API call
      cy.intercept('GET', '**/api/hsm/keys*').as('getKeys')

      cy.visit('/keys')
      cy.wait('@getKeys')
      // Click refresh to ensure we have latest data
      cy.get('button').find('svg.lucide-refresh-cw').parent().click()
      cy.wait('@getKeys')
      cy.contains(testKeyId.substring(0, 8), { timeout: 10000 }).should('exist')

      // Navigate to detail via dropdown menu
      cy.contains(testKeyId.substring(0, 8))
        .parents('tr')
        .within(() => {
          cy.get('button').find('svg.lucide-more-horizontal').parent().click()
        })
      cy.get('[role="menuitem"]').contains('View Details').click()
      cy.url().should('include', testKeyId)

      cy.go('back')
      cy.url().should('include', '/keys')
      cy.url().should('not.include', testKeyId)
    })
  })

  describe('Delete From Detail Page', () => {
    it('shows delete confirmation dialog', () => {
      // Click delete button in header
      cy.contains('button', /delete/i).click()

      cy.get('[role="dialog"]').should('be.visible')
    })

    it('cancels delete when clicking cancel', () => {
      cy.contains('button', /delete/i).click()
      cy.get('[role="dialog"]').should('be.visible')

      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /cancel/i).click()
      })

      cy.get('[role="dialog"]').should('not.exist')
      cy.url().should('include', testKeyId)
    })
  })

  describe('Error Handling', () => {
    it('shows error for non-existent key', () => {
      cy.visit('/keys/non-existent-key-12345', { failOnStatusCode: false })

      // Should show "Key Not Found" message
      cy.contains(/not found|error/i).should('be.visible')
    })
  })

  describe('Algorithm-Specific Details', () => {
    describe('ECDSA Key', () => {
      beforeEach(() => {
        cy.createKeyViaApi({ algorithm: 'ECDSA_P256', purpose: 'SIGN' }).then((key) => {
          cy.deleteKeyViaApi(testKeyId)
          testKeyId = key.key_id
          cy.visit(`/keys/${testKeyId}`)
          cy.wait('@getKey')
          cy.contains('Key Details', { timeout: 10000 }).should('be.visible')
        })
      })

      it('displays ECDSA algorithm details', () => {
        cy.contains('ECDSA P-256').should('be.visible')
      })
    })
  })
})
