#include "EntropyCalculator.h"
#include <cmath>
#include <cctype>

namespace PasswordChecker {

int EntropyCalculator::calculatePoolSize(const std::string& password, 
                                         bool& hasLower, 
                                         bool& hasUpper, 
                                         bool& hasDigit, 
                                         bool& hasSpecial) {
    hasLower = false;
    hasUpper = false;
    hasDigit = false;
    hasSpecial = false;

    for (unsigned char c : password) {
        if (std::islower(c)) {
            hasLower = true;
        } else if (std::isupper(c)) {
            hasUpper = true;
        } else if (std::isdigit(c)) {
            hasDigit = true;
        } else if (std::isprint(c)) {
            // Any printable non-alphanumeric character is counted as a special symbol
            hasSpecial = true;
        } else {
            // Fallback for non-ASCII or non-printable chars (counted as special/other)
            hasSpecial = true;
        }
    }

    int poolSize = 0;
    if (hasLower)   poolSize += 26; // a-z
    if (hasUpper)   poolSize += 26; // A-Z
    if (hasDigit)   poolSize += 10; // 0-9
    if (hasSpecial) poolSize += 33; // Special symbols (standard keyboard punctuation and space)

    return poolSize;
}

double EntropyCalculator::calculateEntropy(const std::string& password) {
    if (password.empty()) {
        return 0.0;
    }

    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    int poolSize = calculatePoolSize(password, hasLower, hasUpper, hasDigit, hasSpecial);

    if (poolSize == 0) {
        return 0.0;
    }

    // Shannon Entropy Formula: E = L * log2(R)
    // where:
    //   L = length of the password
    //   R = pool size of characters used
    //
    // Cyber Security Viva Explanation:
    // - Entropy measures the amount of uncertainty or randomness in a password.
    // - It represents the number of bits required to represent all possible combinations 
    //   of passwords of length L selected from a character set of size R.
    // - A higher entropy means the password is much more resistant to brute-force attacks.
    // - For example, if E = 72, an attacker must try up to 2^72 combinations in a brute-force sweep.
    double L = static_cast<double>(password.length());
    double R = static_cast<double>(poolSize);

    return L * std::log2(R);
}

} // namespace PasswordChecker
