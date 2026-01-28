/// <reference types="cypress" />

describe('Create Key', () => {
  beforeEach(() => {
    cy.setupAuth()
    cy.visit('/keys')
  })

  describe('Dialog Open/Close', () => {
    it('opens create key dialog when clicking Create Key button', () => {
      cy.contains('button', /create key/i).click()

      cy.get('[role="dialog"]').should('be.visible')
      cy.contains('Create New Key').should('be.visible')
    })

    it('closes dialog when clicking cancel', () => {
      cy.contains('button', /create key/i).click()
      cy.get('[role="dialog"]').should('be.visible')

      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /cancel/i).click()
      })

      cy.get('[role="dialog"]').should('not.exist')
    })

    it('closes dialog on Escape key', () => {
      cy.contains('button', /create key/i).click()
      cy.get('[role="dialog"]').should('be.visible')

      cy.get('body').type('{esc}')

      cy.get('[role="dialog"]').should('not.exist')
    })
  })

  describe('Algorithm Selection', () => {
    beforeEach(() => {
      cy.contains('button', /create key/i).click()
    })

    it('displays algorithm dropdown', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.contains(/algorithm/i).should('be.visible')
        cy.get('button[role="combobox"]').first().should('exist')
      })
    })

    it('shows all available algorithms', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })

      // Check for all supported algorithms (using display names)
      cy.get('[role="option"]').contains('Ed25519').should('exist')
      cy.get('[role="option"]').contains('ECDSA').should('exist')
      cy.get('[role="option"]').contains('RSA').should('exist')
    })

    it('selects Ed25519 algorithm', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })
      cy.get('[role="option"]').contains('Ed25519').click()

      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().should('contain.text', 'Ed25519')
      })
    })

    it('selects ECDSA P-256 algorithm', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })
      cy.get('[role="option"]').contains('ECDSA P-256').click()

      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().should('contain.text', 'ECDSA P-256')
      })
    })

    it('selects RSA 4096 algorithm', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })
      cy.get('[role="option"]').contains('RSA 4096').click()

      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().should('contain.text', 'RSA 4096')
      })
    })
  })

  describe('Purpose Selection', () => {
    beforeEach(() => {
      cy.contains('button', /create key/i).click()
    })

    it('displays purpose dropdown', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.contains(/purpose/i).should('be.visible')
      })
    })

    it('shows available purposes', () => {
      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').eq(1).click()
      })

      cy.get('[role="option"]').contains(/sign/i).should('exist')
    })
  })

  describe('Create Key Success', () => {
    afterEach(() => {
      // Cleanup - delete any keys created during tests
      cy.getKeysViaApi().then((keys) => {
        const recentKeys = keys.filter((k) => {
          const created = new Date(k.created_at)
          const now = new Date()
          return now.getTime() - created.getTime() < 60000 // Created in last minute
        })
        recentKeys.forEach((key) => {
          cy.deleteKeyViaApi(key.key_id)
        })
      })
    })

    it('creates Ed25519 key successfully', () => {
      // Open dialog
      cy.contains('button', /create key/i).click()

      // Select Ed25519
      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })
      cy.get('[role="option"]').contains('Ed25519').click()

      // Submit
      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /create/i).click()
      })

      // Should close dialog
      cy.get('[role="dialog"]').should('not.exist')

      // Should show key in list with correct algorithm
      cy.contains('Ed25519').should('be.visible')
    })

    it('creates ECDSA P-256 key successfully', () => {
      cy.contains('button', /create key/i).click()

      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })
      cy.get('[role="option"]').contains('ECDSA P-256').click()

      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /create/i).click()
      })

      cy.get('[role="dialog"]').should('not.exist')
    })

    it('new key appears in the key list', () => {
      // Create a new key
      cy.contains('button', /create key/i).click()
      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })
      cy.get('[role="option"]').contains('Ed25519').click()
      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /create/i).click()
      })

      // Wait for dialog to close and list to update
      cy.get('[role="dialog"]').should('not.exist')

      // Verify new key appears
      cy.contains('Ed25519').should('be.visible')
    })

    it('shows key ID after creation', () => {
      cy.contains('button', /create key/i).click()

      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })
      cy.get('[role="option"]').contains('Ed25519').click()

      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /create/i).click()
      })

      // Key ID should appear in table (UUIDs or similar format)
      cy.get('table tbody tr').first().should('exist')
    })
  })

  describe('Form Validation', () => {
    beforeEach(() => {
      cy.contains('button', /create key/i).click()
    })

    it('requires algorithm selection', () => {
      // Try to submit without selecting algorithm
      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /create/i).click()
      })

      // Should show validation error or not close dialog
      cy.get('[role="dialog"]').should('be.visible')
    })
  })

  describe('Loading State', () => {
    it('shows loading state while creating key', () => {
      cy.intercept('POST', '**/api/hsm/keys', (req) => {
        req.reply((res) => {
          res.delay = 1000 // Delay response
          res.send({ key_id: 'test-key-123', algorithm: 'ED25519', purpose: 'SIGN', created_at: new Date().toISOString() })
        })
      }).as('createKey')

      cy.contains('button', /create key/i).click()
      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })
      cy.get('[role="option"]').contains('Ed25519').click()

      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /create/i).click()

        // Should show loading indicator or disabled state
        cy.get('button').contains(/create/i).should('be.disabled')
      })
    })
  })
})
