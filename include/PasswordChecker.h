#pragma once
#include <string>
#include <vector>
#include "PasswordDictionary.h"

namespace PasswordChecker {

enum class StrengthLevel {
    VeryWeak,
    Weak,
    Medium,
    Strong,
    VeryStrong
};

struct AnalysisResult {
    std::string password;
    int score = 0;                  // 0 to 100
    StrengthLevel strength = StrengthLevel::VeryWeak;
    double entropy = 0.0;           // Shannon entropy in bits
    std::string crackTimeStr;       // Human-readable estimated crack time

    // Criteria checkboxes
    bool hasMinLength = false;      // >= 12 chars
    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    // Pattern flags
    bool hasRepeats = false;
    std::string repeatsDetails;

    bool hasSeqNumbers = false;
    std::string seqNumbersDetails;

    bool hasSeqAlphabets = false;
    std::string seqAlphabetsDetails;

    bool hasKeyboardPatterns = false;
    std::string keyboardPatternsDetails;

    // Dictionary matches
    bool isCommon = false;
    bool containsDictWord = false;
    std::string dictWordDetails;

    // List of improvement recommendations
    std::vector<std::string> suggestions;
};

class PasswordChecker {
public:
    // Performs a comprehensive security analysis of the password, using the offline dictionary.
    static AnalysisResult analyze(const std::string& password, const PasswordDictionary& dictionary);

    // Estimates cracking time based on entropy value
    static std::string estimateCrackTime(double entropy);

    // Helper to get string representation of strength level
    static std::string getStrengthLevelName(StrengthLevel level);
};

} // namespace PasswordChecker
