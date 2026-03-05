import LoginPage from '../pages/LoginPage';
import InventoryPage from '../pages/InventoryPage';

describe('Login Functionality', () => {
  beforeEach(() => {
    LoginPage.visit();
  });

  it('TC-01: should login successfully with valid credentials', () => {
    cy.fixture('users').then((users) => {
      LoginPage.login(users.standardUser.username, users.standardUser.password);
      InventoryPage.verifyPageLoaded();
    });
  });

  it('TC-02: should show error for locked out user', () => {
    cy.fixture('users').then((users) => {
      LoginPage.login(users.lockedUser.username, users.lockedUser.password);
      LoginPage.verifyErrorMessage('Sorry, this user has been locked out');
    });
  });

  it('TC-03: should show error for invalid credentials', () => {
    cy.fixture('users').then((users) => {
      LoginPage.login(users.invalidUser.username, users.invalidUser.password);
      LoginPage.verifyErrorMessage(
        'Username and password do not match any user in this service'
      );
    });
  });

  it('TC-04: should show error when username is empty', () => {
    LoginPage.passwordInput.type('secret_sauce');
    LoginPage.clickLogin();
    LoginPage.verifyErrorMessage('Username is required');
  });

  it('TC-05: should show error when password is empty', () => {
    LoginPage.usernameInput.type('standard_user');
    LoginPage.clickLogin();
    LoginPage.verifyErrorMessage('Password is required');
  });
});
