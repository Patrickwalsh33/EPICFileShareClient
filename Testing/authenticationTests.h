#pragma once

#include <string>
#include <vector>
#include <functional>
#include <iostream>

// Simple test framework
class TestResult {
public:
    bool passed;
    std::string testName;
    std::string message;

    TestResult(const std::string& name, bool success, const std::string& msg = "")
            : testName(name), passed(success), message(msg) {}
};

class TestSuite {
public:
    TestSuite(const std::string& suiteName);
    virtual ~TestSuite() = default;

    void addTest(const std::string& testName, std::function<bool()> testFunc);

    void runTests();

    const std::vector<TestResult>& getResults() const { return results; }

    void printSummary() const;

protected:
    std::string suiteName;
    std::vector<std::pair<std::string, std::function<bool()>>> tests;
    std::vector<TestResult> results;
};

// Authentication test class
class AuthenticationTests : public TestSuite {
public:
    AuthenticationTests();

    virtual void setUp() {}
    virtual void tearDown() {}

    static void runAllTests();

private:

    bool testPasswordValidation();
    bool testUsernameValidation();
    bool testRegistrationValidation();
    bool testLoginValidation();
    bool testPasswordStrength();
    bool testInputSanitization();
};