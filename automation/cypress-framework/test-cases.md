# Test Cases — Cypress E2E (Sauce Demo)

## Login Functionality

### TC-01: Valid login with standard user
- **Steps:** Visit login page → Enter standard_user / secret_sauce → Click Login
- **Expected:** Redirected to inventory page, URL contains `/inventory.html`, title shows "Products"

### TC-02: Locked out user cannot login
- **Steps:** Visit login page → Enter locked_out_user / secret_sauce → Click Login
- **Expected:** Error message visible: "Sorry, this user has been locked out"

### TC-03: Invalid credentials show error
- **Steps:** Visit login page → Enter invalid_user / wrong_password → Click Login
- **Expected:** Error message: "Username and password do not match any user in this service"

### TC-04: Empty username shows error
- **Steps:** Visit login page → Leave username empty → Enter password → Click Login
- **Expected:** Error message: "Username is required"

### TC-05: Empty password shows error
- **Steps:** Visit login page → Enter username → Leave password empty → Click Login
- **Expected:** Error message: "Password is required"

---

## Inventory Page

### TC-06: All 6 products displayed
- **Steps:** Login as standard user → Check inventory page
- **Expected:** Exactly 6 product items visible

### TC-07: Correct product names and prices
- **Steps:** Login as standard user → Verify each product name and price against fixture data
- **Expected:** All 6 products match expected names and prices from `products.json`

### TC-08: Logout returns to login page
- **Steps:** Login → Open burger menu → Click Logout
- **Expected:** Redirected to login page (saucedemo.com root)

---

## Shopping Cart

### TC-09: Add single item — cart badge shows 1
- **Steps:** Login → Add "Sauce Labs Backpack" to cart
- **Expected:** Cart badge shows "1"

### TC-10: Add multiple items — cart badge updates
- **Steps:** Login → Add "Sauce Labs Backpack" → Add "Sauce Labs Bike Light"
- **Expected:** Cart badge shows "2"

### TC-11: Remove item from inventory page
- **Steps:** Login → Add Backpack → Verify badge is 1 → Click Remove on Backpack
- **Expected:** Cart badge disappears (no items)

### TC-12: Cart page shows correct items and prices
- **Steps:** Login → Add Backpack ($29.99) and Onesie ($7.99) → Go to cart
- **Expected:** Cart shows both items with correct prices, total 2 items

### TC-13: Remove item from cart page
- **Steps:** Login → Add Backpack and Bike Light → Go to cart → Remove Backpack
- **Expected:** Only Bike Light remains, cart shows 1 item, Backpack is gone

### TC-14: Continue Shopping returns to inventory
- **Steps:** Login → Go to cart → Click "Continue Shopping"
- **Expected:** Redirected to inventory page

---

## Checkout Flow

### TC-15: Complete checkout — happy path
- **Steps:** Login → Add item → Cart → Checkout → Fill info (Bhanu, Gupta, 9016) → Continue → Finish
- **Expected:** Order confirmation page with "Thank you for your order!"

### TC-16: Missing first name shows error
- **Steps:** Login → Add item → Cart → Checkout → Leave first name empty → Click Continue
- **Expected:** Error: "First Name is required"

### TC-17: Missing last name shows error
- **Steps:** Login → Add item → Cart → Checkout → Fill first name only → Click Continue
- **Expected:** Error: "Last Name is required"

### TC-18: Missing postal code shows error
- **Steps:** Login → Add item → Cart → Checkout → Fill name fields only → Click Continue
- **Expected:** Error: "Postal Code is required"

### TC-19: Cancel checkout returns to cart
- **Steps:** Login → Add item → Cart → Checkout → Click Cancel
- **Expected:** Redirected back to cart page

### TC-20: Back Home after purchase returns to inventory
- **Steps:** Complete full checkout → Click "Back Home"
- **Expected:** Redirected to inventory page

---

## Product Sorting

### TC-21: Sort by Name (A to Z)
- **Steps:** Login → Select "Name (A to Z)" from dropdown
- **Expected:** Products ordered alphabetically A-Z matching fixture data

### TC-22: Sort by Name (Z to A)
- **Steps:** Login → Select "Name (Z to A)" from dropdown
- **Expected:** Products ordered alphabetically Z-A matching fixture data

### TC-23: Sort by Price (low to high)
- **Steps:** Login → Select "Price (low to high)" from dropdown
- **Expected:** Product prices in ascending order

### TC-24: Sort by Price (high to low)
- **Steps:** Login → Select "Price (high to low)" from dropdown
- **Expected:** Product prices in descending order
