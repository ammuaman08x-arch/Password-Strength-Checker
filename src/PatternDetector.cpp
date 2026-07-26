#include "PatternDetector.h"
#include <cctype>
#include <algorithm>
#include <vector>

namespace PasswordChecker {

// Helper to convert character to lowercase for standard comparisons
static char toLowerChar(char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

bool PatternDetector::hasRepeatedCharacters(const std::string& password, std::string& details) {
    if (password.length() < 3) {
        return false;
    }

    for (size_t i = 0; i <= password.length() - 3; ++i) {
        if (password[i] == password[i + 1] && password[i + 1] == password[i + 2]) {
            details = "Repeated character run found: '" + password.substr(i, 3) + "'";
            return true;
        }
    }
    return false;
}

bool PatternDetector::hasSequentialNumbers(const std::string& password, std::string& details) {
    if (password.length() < 3) {
        return false;
    }

    for (size_t i = 0; i <= password.length() - 3; ++i) {
        char c1 = password[i];
        char c2 = password[i + 1];
        char c3 = password[i + 2];

        if (std::isdigit(static_cast<unsigned char>(c1)) &&
            std::isdigit(static_cast<unsigned char>(c2)) &&
            std::isdigit(static_cast<unsigned char>(c3))) {
            
            // Ascending sequence (e.g., '123')
            if (c2 == c1 + 1 && c3 == c2 + 1) {
                details = "Ascending number sequence found: '" + password.substr(i, 3) + "'";
                return true;
            }
            // Descending sequence (e.g., '321')
            if (c2 == c1 - 1 && c3 == c2 - 1) {
                details = "Descending number sequence found: '" + password.substr(i, 3) + "'";
                return true;
            }
        }
    }
    return false;
}

bool PatternDetector::hasSequentialAlphabets(const std::string& password, std::string& details) {
    if (password.length() < 3) {
        return false;
    }

    for (size_t i = 0; i <= password.length() - 3; ++i) {
        char c1 = toLowerChar(password[i]);
        char c2 = toLowerChar(password[i + 1]);
        char c3 = toLowerChar(password[i + 2]);

        if (std::isalpha(static_cast<unsigned char>(c1)) &&
            std::isalpha(static_cast<unsigned char>(c2)) &&
            std::isalpha(static_cast<unsigned char>(c3))) {

            // Ascending alphabetical sequence (e.g., 'abc')
            if (c2 == c1 + 1 && c3 == c2 + 1) {
                details = "Ascending alphabetical sequence found: '" + password.substr(i, 3) + "'";
                return true;
            }
            // Descending alphabetical sequence (e.g., 'cba')
            if (c2 == c1 - 1 && c3 == c2 - 1) {
                details = "Descending alphabetical sequence found: '" + password.substr(i, 3) + "'";
                return true;
            }
        }
    }
    return false;
}

bool PatternDetector::hasKeyboardPatterns(const std::string& password, std::string& details) {
    if (password.length() < 3) {
        return false;
    }

    // Standard QWERTY keyboard rows (lowercase)
    const std::vector<std::string> keyboardRows = {
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    };

    // Also search reversed rows for backwards sequences (e.g. "rewq")
    std::vector<std::string> searchRows = keyboardRows;
    for (const auto& row : keyboardRows) {
        std::string revRow = row;
        std::reverse(revRow.begin(), revRow.end());
        searchRows.push_back(revRow);
    }

    for (size_t i = 0; i <= password.length() - 3; ++i) {
        std::string sub = password.substr(i, 3);
        // Convert substring to lowercase for keyboard check
        std::string subLower = sub;
        std::transform(subLower.begin(), subLower.end(), subLower.begin(), toLowerChar);

        for (const auto& row : searchRows) {
            if (row.find(subLower) != std::string::npos) {
                details = "Keyboard pattern found: '" + sub + "'";
                return true;
            }
        }
    }
    return false;
}

} // namespace PasswordChecker
