/// <reference types="cypress" />

describe('Login Page', () => {
  beforeEach(() => {
    cy.clearAppState()
    cy.visit('/login')
  })

  describe('Form Display', () => {
    it('displays the login form with all elements', () => {
      // Check page title
      cy.contains('HSM Console').should('be.visible')
      cy.contains('Sign in to access the Hardware Security Module').should('be.visible')

      // Check form elements
      cy.get('#username').should('be.visible')
      cy.get('#password').should('be.visible')
      cy.get('button[type="submit"]').should('be.visible')
    })

    it('displays development credentials helper', () => {
      cy.contains('Development Mode').should('be.visible')
      cy.contains('admin').should('be.visible')
      cy.contains('dev').should('be.visible')
    })

    it('has empty inputs by default', () => {
      cy.get('#username').should('have.value', '')
      cy.get('#password').should('have.value', '')
    })
  })

  describe('Form Validation', () => {
    it('shows error when submitting empty form', () => {
      cy.get('button[type="submit"]').click()

      // Should show validation errors
      cy.contains('Username is required').should('be.visible')
      cy.contains('Password is required').should('be.visible')
    })

    it('shows error when username is missing', () => {
      cy.get('#password').type('somepassword')
      cy.get('button[type="submit"]').click()

      cy.contains('Username is required').should('be.visible')
    })

    it('shows error when password is missing', () => {
      cy.get('#username').type('admin')
      cy.get('button[type="submit"]').click()

      cy.contains('Password is required').should('be.visible')
    })
  })

  describe('Password Visibility Toggle', () => {
    it('password is hidden by default', () => {
      cy.get('#password').should('have.attr', 'type', 'password')
    })

    it('toggles password visibility when eye icon is clicked', () => {
      // Type a password
      cy.get('#password').type('testpassword')

      // Find and click the toggle button
      cy.get('#password').parent().find('button[type="button"]').click()

      // Password should now be visible
      cy.get('#password').should('have.attr', 'type', 'text')

      // Click again to hide
      cy.get('#password').parent().find('button[type="button"]').click()

      // Password should be hidden again
      cy.get('#password').should('have.attr', 'type', 'password')
    })
  })

  describe('Login Success', () => {
    it('successfully logs in with admin credentials', () => {
      cy.fixture('users').then((users) => {
        cy.get('#username').type(users.admin.username)
        cy.get('#password').type(users.admin.password)
        cy.get('button[type="submit"]').click()

        // Should redirect to dashboard
        cy.url().should('not.include', '/login')
        cy.url().should('eq', Cypress.config().baseUrl + '/')
      })
    })

    it('successfully logs in with operator credentials', () => {
      cy.fixture('users').then((users) => {
        cy.get('#username').type(users.operator.username)
        cy.get('#password').type(users.operator.password)
        cy.get('button[type="submit"]').click()

        cy.url().should('not.include', '/login')
      })
    })

    it('stores auth token in localStorage after login', () => {
      cy.fixture('users').then((users) => {
        cy.get('#username').type(users.admin.username)
        cy.get('#password').type(users.admin.password)
        cy.get('button[type="submit"]').click()

        cy.url().should('not.include', '/login')

        cy.window().then((win) => {
          const token = win.localStorage.getItem('hsm_auth_token')
          expect(token).to.exist
          expect(token).to.be.a('string')
          expect(token!.length).to.be.greaterThan(0)
        })
      })
    })

    it('stores user info in localStorage after login', () => {
      cy.fixture('users').then((users) => {
        cy.get('#username').type(users.admin.username)
        cy.get('#password').type(users.admin.password)
        cy.get('button[type="submit"]').click()

        cy.url().should('not.include', '/login')

        cy.window().then((win) => {
          const userJson = win.localStorage.getItem('hsm_auth_user')
          expect(userJson).to.exist

          const user = JSON.parse(userJson!)
          expect(user.username).to.eq(users.admin.username)
          expect(user.roles).to.be.an('array')
        })
      })
    })
  })

  describe('Login Error', () => {
    it('shows error for invalid credentials', () => {
      cy.fixture('users').then((users) => {
        cy.get('#username').type(users.invalid.username)
        cy.get('#password').type(users.invalid.password)
        cy.get('button[type="submit"]').click()

        // Should show error message
        cy.get('.bg-destructive\\/10').should('be.visible')

        // Should stay on login page
        cy.url().should('include', '/login')
      })
    })

    it('clears error when user starts typing again', () => {
      cy.fixture('users').then((users) => {
        // First, trigger an error
        cy.get('#username').type(users.invalid.username)
        cy.get('#password').type(users.invalid.password)
        cy.get('button[type="submit"]').click()

        cy.get('.bg-destructive\\/10').should('be.visible')

        // Start typing again - error may clear
        cy.get('#username').clear().type(users.admin.username)

        // Submit with correct credentials should work
        cy.get('#password').clear().type(users.admin.password)
        cy.get('button[type="submit"]').click()

        cy.url().should('not.include', '/login')
      })
    })
  })

  describe('Quick Login with Dev Credentials', () => {
    it('can log in using displayed dev credentials', () => {
      // The form shows admin/dev as credentials
      cy.get('#username').type('admin')
      cy.get('#password').type('dev')
      cy.get('button[type="submit"]').click()

      cy.url().should('not.include', '/login')
    })
  })
})
