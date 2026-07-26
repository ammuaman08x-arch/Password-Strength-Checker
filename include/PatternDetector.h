#pragma once
#include <string>

namespace PasswordChecker {

class PatternDetector {
public:
    // Scans for repeated characters (e.g., "aaa", "111") of length >= 3.
    // If found, returns true and describes it in 'details'.
    static bool hasRepeatedCharacters(const std::string& password, std::string& details);

    // Scans for sequential numbers (e.g., "123", "987", "345") of length >= 3.
    // If found, returns true and describes it in 'details'.
    static bool hasSequentialNumbers(const std::string& password, std::string& details);

    // Scans for sequential alphabets (e.g., "abc", "xyz", "cba") of length >= 3.
    // If found, returns true and describes it in 'details'.
    static bool hasSequentialAlphabets(const std::string& password, std::string& details);

    // Scans for sequential keyboard patterns (e.g., "qwer", "asdf", "zxcv") of length >= 3.
    // If found, returns true and describes it in 'details'.
    static bool hasKeyboardPatterns(const std::string& password, std::string& details);
};

} // namespace PasswordChecker
