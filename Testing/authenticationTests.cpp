#include "authenticationTests.h"
#include "../auth/validation.h"
#include "../auth/CommonPasswordChecker.h"
#include <QString>
#include <iostream>

TestSuite::TestSuite(const std::string& suiteName) : suiteName(suiteName) {}

void TestSuite::addTest(const std::string& testName, std::function<bool()> testFunc) {
    tests.emplace_back(testName, testFunc);
}

void TestSuite::runTests() {
    results.clear();

    std::cout << "Running test suite: " << suiteName << std::endl;

    for (const auto& test : tests) {
        std::cout << "Running: " << test.first << "... ";

        try {
            bool result = test.second();
            results.emplace_back(test.first, result, result ? "PASSED" : "FAILED");
            std::cout << (result ? "PASSED" : "FAILED") << std::endl;
        } catch (const std::exception& e) {
            results.emplace_back(test.first, false, "EXCEPTION: " + std::string(e.what()));
            std::cout << "EXCEPTION: " << e.what() << std::endl;
        }
    }
}

void TestSuite::printSummary() const {
    int passed = 0;
    int total = results.size();

    for (const auto& result : results) {
        if (result.passed) passed++;
    }


    std::cout << "Test Suite: " << suiteName << std::endl;
    std::cout << "Results: " << passed << "/" << total << " tests passed" << std::endl;

    if (passed != total) {
        std::cout << "\nFailed tests:" << std::endl;
        for (const auto& result : results) {
            if (!result.passed) {
                std::cout << "  - " << result.testName << ": " << result.message << std::endl;
            }
        }
    }

}

// AuthenticationTests implementation
AuthenticationTests::AuthenticationTests() : TestSuite("Authentication Tests") {
    // Register test methods
    addTest("Password Validation", [this]() { return testPasswordValidation(); });
    addTest("Username Validation", [this]() { return testUsernameValidation(); });
    addTest("Registration Validation", [this]() { return testRegistrationValidation(); });
    addTest("Login Validation", [this]() { return testLoginValidation(); });
    addTest("Password Strength", [this]() { return testPasswordStrength(); });
    addTest("Input Sanitization", [this]() { return testInputSanitization(); });
}

void AuthenticationTests::runAllTests() {
    std::cout << "Starting Authentication Test Suite" << std::endl;


    AuthenticationTests authTests;

    authTests.setUp();
    authTests.runTests();
    authTests.printSummary();
    authTests.tearDown();

    // Checks if all tests have  passed
    const auto& results = authTests.getResults();
    bool allPassed = true;
    for (const auto& result : results) {
        if (!result.passed) {
            allPassed = false;
            break;
        }
    }

    std::cout << "Overall result: " << (allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << std::endl;
}

bool AuthenticationTests::testPasswordValidation() {
    // Create CommonPasswordChecker with default constructor
    CommonPasswordChecker checker;
    PasswordValidator validator(&checker);
    QString errorMsg;

    // Test if password is valid
    QString validPass = "StrongPassword123!";
    QString confirmPass = "StrongPassword123!";

    if (!validator.validatePassword(validPass, confirmPass, errorMsg)) {
        std::cout << "\n  [DEBUG] Valid password failed: " << errorMsg.toStdString();
        return false;
    }

    // Test password mismatch
    QString mismatchPass = "DifferentPassword123!";
    if (validator.validatePassword(validPass, mismatchPass, errorMsg)) {
        std::cout << "\n  [DEBUG] Password mismatch should have failed but passed";
        return false; // Should fail
    }

    // Test weak password
    QString weakPass = "123";
    if (validator.validatePassword(weakPass, weakPass, errorMsg)) {
        std::cout << "\n  [DEBUG] Weak password should have failed but passed";
        return false; // Should fail
    }

    return true;
}

bool AuthenticationTests::testUsernameValidation() {
    CommonPasswordChecker checker;
    PasswordValidator validator(&checker);
    QString errorMsg;

    // Test valid username
    QString validUsername = "validuser123";
    if (!validator.validateUsername(validUsername, errorMsg)) {
        std::cout << "\n  [DEBUG] Valid username '" << validUsername.toStdString()
                  << "' failed: " << errorMsg.toStdString();
        return false;
    }

    // Test too short username (less than 6 characters)
    QString shortUsername = "abc";
    if (validator.validateUsername(shortUsername, errorMsg)) {
        std::cout << "\n  [DEBUG] Short username should have failed but passed";
        return false; // Should fail
    }

    // Test too long username (more than 50 characters - this is definitely over 50)
    QString longUsername = "thisusernameiswaywaywaywaywaywaywaywaytoooooooooooooolong";
    std::cout << "\n  [DEBUG] Testing username length: " << longUsername.length() << " characters";
    if (validator.validateUsername(longUsername, errorMsg)) {
        std::cout << "\n  [DEBUG] Long username should have failed but passed";
        return false; // Should fail
    }

    // Test reserved username
    QString reservedUsername = "admin";
    if (validator.validateUsername(reservedUsername, errorMsg)) {
        std::cout << "\n  [DEBUG] Reserved username should have failed but passed";
        return false; // Should fail
    }

    // Test username with invalid characters
    QString invalidUsername = "user@domain.com";
    if (validator.validateUsername(invalidUsername, errorMsg)) {
        std::cout << "\n  [DEBUG] Invalid character username should have failed but passed";
        return false; // Should fail
    }

    return true;
}

bool AuthenticationTests::testRegistrationValidation() {
    // Test the combination of username and password validation
    QString username = "newuser123";
    QString password = "SecurePassword123!";
    QString confirmPassword = "SecurePassword123!";
    QString errorMsg;

    CommonPasswordChecker checker;
    PasswordValidator validator(&checker);

    // Both should pass
    bool usernameValid = validator.validateUsername(username, errorMsg);
    if (!usernameValid) {
        std::cout << "\n  [DEBUG] Registration username validation failed: " << errorMsg.toStdString();
    }

    bool passwordValid = validator.validatePassword(password, confirmPassword, errorMsg);
    if (!passwordValid) {
        std::cout << "\n  [DEBUG] Registration password validation failed: " << errorMsg.toStdString();
    }

    return usernameValid && passwordValid;
}

bool AuthenticationTests::testLoginValidation() {
    // Test login-specific validation scenarios
    QString username = "existinguser";
    QString password = "UserPassword123!";
    QString errorMsg;

    CommonPasswordChecker checker;
    PasswordValidator validator(&checker);

    // For login, we only validate format, not strength
    bool usernameValid = validator.validateUsername(username, errorMsg);
    if (!usernameValid) {
        std::cout << "\n  [DEBUG] Login username validation failed: " << errorMsg.toStdString();
    }

    // For login, password just needs to be sanitized
    QString sanitizedPassword = password;
    bool passwordValid = InputSanitizer::sanitizePassword(sanitizedPassword, errorMsg);
    if (!passwordValid) {
        std::cout << "\n  [DEBUG] Login password sanitization failed: " << errorMsg.toStdString();
    }

    return usernameValid && passwordValid;
}

bool AuthenticationTests::testPasswordStrength() {
    CommonPasswordChecker checker;
    PasswordValidator validator(&checker);
    QString errorMsg;

    // Test common password (should fail)
    QString commonPass = "password123";
    if (validator.validatePassword(commonPass, commonPass, errorMsg)) {
        std::cout << "\n  [DEBUG] Common password should have failed but passed";
        return false; // Should fail
    }

    // Test strong password (should pass)
    QString strongPass = "MyVerySecureP@ssw0rd2024!";
    if (!validator.validatePassword(strongPass, strongPass, errorMsg)) {
        std::cout << "\n  [DEBUG] Strong password failed: " << errorMsg.toStdString();
        return false;
    }

    return true;
}

bool AuthenticationTests::testInputSanitization() {
    QString errorMsg;

    // Test username sanitization
    QString username = "normaluser";
    QString originalUsername = username;
    bool usernameResult = InputSanitizer::sanitizeUsername(username, errorMsg);

    if (!usernameResult) {
        std::cout << "\n  [DEBUG] Normal username sanitization failed: " << errorMsg.toStdString();
        return false;
    }
    if (username != originalUsername) {
        std::cout << "\n  [DEBUG] Username was modified during sanitization";
        return false;
    }

    // Test password sanitization
    QString password = "NormalPassword123!";
    QString originalPassword = password;
    bool passwordResult = InputSanitizer::sanitizePassword(password, errorMsg);

    if (!passwordResult) {
        std::cout << "\n  [DEBUG] Normal password sanitization failed: " << errorMsg.toStdString();
        return false;
    }
    if (password != originalPassword) {
        std::cout << "\n  [DEBUG] Password was modified during sanitization";
        return false;
    }

    // Test dangerous input (should be rejected)
    QString dangerousInput = "<script>alert('xss')</script>";
    bool dangerousResult = InputSanitizer::sanitizeUsername(dangerousInput, errorMsg);

    if (dangerousResult) {
        std::cout << "\n  [DEBUG] Dangerous input should have been rejected but passed";
        return false; // Should fail
    }

    return true;
}