#pragma once
#include <string>

namespace PasswordChecker {

class EntropyCalculator {
public:
    // Calculates the Shannon entropy of the password in bits.
    // Entropy (E) is calculated as: E = L * log2(R)
    // where L is the length of the password and R is the size of the character pool (charset).
    static double calculateEntropy(const std::string& password);

    // Evaluates character classes present in the password and returns the size of the pool.
    // Also outputs booleans indicating the presence of lower, upper, digits, and special characters.
    static int calculatePoolSize(const std::string& password, 
                                 bool& hasLower, 
                                 bool& hasUpper, 
                                 bool& hasDigit, 
                                 bool& hasSpecial);
};

} // namespace PasswordChecker
