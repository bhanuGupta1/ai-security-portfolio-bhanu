# Test Plan — Cypress E2E Automation (Sauce Demo)

## Objective

Demonstrate professional Cypress test automation skills by building a complete E2E framework against a real e-commerce application, using industry-standard patterns and practices.

## Application Under Test

[Sauce Demo](https://www.saucedemo.com) — a practice e-commerce site with authentication, product catalogue, shopping cart, checkout flow, and sorting functionality.

## Scope (In)

- Login functionality — valid, invalid, locked, and empty credential scenarios
- Inventory page — product display, count, pricing, and logout
- Shopping cart — add, remove, verify items and prices, continue shopping
- Checkout flow — happy path, missing field validation, cancel, post-purchase navigation
- Product sorting — name (A-Z, Z-A) and price (low-high, high-low)

## Out of Scope

- Cross-browser testing (covered in Playwright framework)
- Mobile responsive testing (covered in Playwright framework)
- API-level testing (covered in API testing section)
- Performance or load testing
- Visual regression testing

## Test Approach

- **Page Object Model** for maintainability and reusability
- **Custom commands** for common actions (login, add to cart)
- **Data-driven testing** via fixtures (user credentials, product data)
- **Positive and negative tests** for each feature area
- **CI/CD integration** via GitHub Actions

## Tools

- Cypress 15.x
- JavaScript (ES6)
- GitHub Actions (CI)
- Chrome (default browser)

## Environment

- URL: https://www.saucedemo.com
- Browser: Chrome (headless in CI, headed locally)
- Viewport: 1280 x 720

## Entry Criteria

- Node.js installed
- Dependencies installed (`npm install`)
- Sauce Demo site is accessible

## Exit Criteria

- All 24 test cases pass in both UI runner and headless CLI
- Tests pass in GitHub Actions CI pipeline
- Evidence screenshots captured
- Test summary updated with results
