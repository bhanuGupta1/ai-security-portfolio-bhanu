# Test Summary — Cypress E2E Automation (Sauce Demo)

## Execution

- **Tool:** Cypress 15.x (UI Runner + Headless CLI)
- **Site:** https://www.saucedemo.com
- **Date:** 06/03/2026
- **Browser:** Chrome
- **CI:** GitHub Actions

## Results

| Spec | Tests | Passed | Failed |
|------|-------|--------|--------|
| login.cy.js | 5 | 5 | 0 |
| inventory.cy.js | 3 | 3 | 0 |
| cart.cy.js | 6 | 6 | 0 |
| checkout.cy.js | 6 | 6 | 0 |
| sorting.cy.js | 4 | 4 | 0 |
| **Total** | **24** | **24** | **0** |

## Framework Highlights

- **Page Object Model** — 4 page classes (`LoginPage`, `InventoryPage`, `CartPage`, `CheckoutPage`) for clean separation of selectors and actions
- **Custom Commands** — `cy.login()`, `cy.loginAs()`, `cy.addToCart()`, `cy.verifyCartCount()` for reusability
- **Data-Driven Tests** — Fixture files for user credentials (6 user types including locked/invalid) and product data (names, prices, sort orders)
- **Negative Testing** — Invalid credentials, locked users, empty fields, missing checkout info
- **CI/CD** — GitHub Actions runs all 24 tests on every push with screenshot upload on failure

## Key Observations

- Sauce Demo uses `data-test` attributes consistently, making selectors stable and reliable
- Sorting tests validate actual DOM order against expected fixture data, not just visual appearance
- Checkout negative tests cover all 3 required fields independently
- Cart badge correctly disappears (removed from DOM) when cart is empty rather than showing "0"

## Evidence

- Full test run recording: `cypress/evidence/` (screen recording of all 24 tests passing)
- Old evidence from previous demo site tests also retained for reference
