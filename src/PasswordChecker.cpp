#include "PasswordChecker.h"
#include "EntropyCalculator.h"
#include "PatternDetector.h"
#include <algorithm>
#include <cmath>

namespace PasswordChecker {

std::string PasswordChecker::getStrengthLevelName(StrengthLevel level) {
    switch (level) {
        case StrengthLevel::VeryWeak:   return "Very Weak";
        case StrengthLevel::Weak:       return "Weak";
        case StrengthLevel::Medium:     return "Medium";
        case StrengthLevel::Strong:     return "Strong";
        case StrengthLevel::VeryStrong: return "Very Strong";
        default:                        return "Unknown";
    }
}

std::string PasswordChecker::estimateCrackTime(double entropy) {
    if (entropy <= 0.0) {
        return "Instant";
    }

    // Assumptions:
    // - Offline attack guessing speed: 10,000,000,000 (10^10) guesses/sec
    // - Average search space size is 2^(E-1)
    // - To prevent floating-point overflow for large entropy values, we calculate the log10 of time.
    //
    // E = entropy
    // Time in seconds: T = 2^(E-1) / 10^10
    // log10(T) = (E - 1) * log10(2) - log10(10^10)
    // log10(T) = (E - 1) * 0.30102999566 - 10
    double log10T = (entropy - 1.0) * 0.30102999566 - 10.0;

    if (log10T < 0.0) {
        return "Instant";
    }
    
    // Convert log10T to seconds and scale:
    // 60 seconds = 1.778 log10
    // 3600 seconds (1 hour) = 3.556 log10
    // 86400 seconds (1 day) = 4.936 log10
    // 30 days = 6.413 log10
    // 365 days (1 year) = 7.498 log10
    // 100 years = 9.498 log10
    // 10,000 years = 11.498 log10

    if (log10T < 1.778) {
        double seconds = std::pow(10.0, log10T);
        if (seconds < 2.0) return "1 second";
        return std::to_string(static_cast<int>(seconds)) + " seconds";
    } else if (log10T < 3.556) {
        double minutes = std::pow(10.0, log10T - 1.778);
        if (minutes < 2.0) return "1 minute";
        return std::to_string(static_cast<int>(minutes)) + " minutes";
    } else if (log10T < 4.936) {
        double hours = std::pow(10.0, log10T - 3.556);
        if (hours < 2.0) return "1 hour";
        return std::to_string(static_cast<int>(hours)) + " hours";
    } else if (log10T < 6.413) {
        double days = std::pow(10.0, log10T - 4.936);
        if (days < 2.0) return "1 day";
        return std::to_string(static_cast<int>(days)) + " days";
    } else if (log10T < 7.498) {
        double months = std::pow(10.0, log10T - 6.413);
        if (months < 2.0) return "1 month";
        return std::to_string(static_cast<int>(months)) + " months";
    } else if (log10T < 9.498) {
        double years = std::pow(10.0, log10T - 7.498);
        if (years < 2.0) return "1 year";
        return std::to_string(static_cast<int>(years)) + " years";
    } else if (log10T < 11.498) {
        double centuries = std::pow(10.0, log10T - 9.498);
        if (centuries < 2.0) return "1 century";
        return std::to_string(static_cast<int>(centuries)) + " centuries";
    } else {
        return "Eternity (Millions of Years)";
    }
}

AnalysisResult PasswordChecker::analyze(const std::string& password, const PasswordDictionary& dictionary) {
    AnalysisResult result;
    result.password = password;

    if (password.empty()) {
        result.score = 0;
        result.strength = StrengthLevel::VeryWeak;
        result.entropy = 0.0;
        result.crackTimeStr = "Instant";
        result.suggestions.push_back("Enter a password to begin analysis.");
        return result;
    }

    // 1. Character class checks and Pool Size calculation
    int poolSize = EntropyCalculator::calculatePoolSize(password, 
                                                         result.hasLower, 
                                                         result.hasUpper, 
                                                         result.hasDigit, 
                                                         result.hasSpecial);
    result.hasMinLength = (password.length() >= 12);

    // 2. Entropy calculation
    result.entropy = EntropyCalculator::calculateEntropy(password);
    
    // 3. Crack time estimation
    result.crackTimeStr = estimateCrackTime(result.entropy);

    // 4. Pattern checks
    result.hasRepeats = PatternDetector::hasRepeatedCharacters(password, result.repeatsDetails);
    result.hasSeqNumbers = PatternDetector::hasSequentialNumbers(password, result.seqNumbersDetails);
    result.hasSeqAlphabets = PatternDetector::hasSequentialAlphabets(password, result.seqAlphabetsDetails);
    result.hasKeyboardPatterns = PatternDetector::hasKeyboardPatterns(password, result.keyboardPatternsDetails);

    // 5. Dictionary checks
    result.isCommon = dictionary.isCommonPassword(password);
    std::string matchedWord;
    result.containsDictWord = dictionary.containsDictionaryWord(password, matchedWord);
    if (result.containsDictWord) {
        result.dictWordDetails = "Contains dictionary word: '" + matchedWord + "'";
    }

    // 6. Score calculation (0 to 100)
    double rawScore = 0.0;

    // Base score from entropy (maps entropy of up to 80 bits to 60 points)
    double entropyScore = (result.entropy / 80.0) * 60.0;
    if (entropyScore > 60.0) {
        entropyScore = 60.0;
    }
    rawScore += entropyScore;

    // Character variety bonuses (up to 40 points)
    if (result.hasLower)   rawScore += 10.0;
    if (result.hasUpper)   rawScore += 10.0;
    if (result.hasDigit)   rawScore += 10.0;
    if (result.hasSpecial) rawScore += 10.0;

    // Deductions/Penalties
    double penalties = 0.0;
    if (password.length() < 8) {
        penalties += 20.0;
    }
    if (result.hasRepeats) {
        penalties += 10.0;
    }
    if (result.hasSeqNumbers) {
        penalties += 10.0;
    }
    if (result.hasSeqAlphabets) {
        penalties += 10.0;
    }
    if (result.hasKeyboardPatterns) {
        penalties += 10.0;
    }
    if (result.containsDictWord) {
        penalties += 25.0;
    }

    rawScore -= penalties;

    // If it's a known common password, force the score to a fail level (0-5 range)
    if (result.isCommon) {
        result.score = 5;
    } else {
        result.score = static_cast<int>(std::round(rawScore));
        if (result.score < 0) result.score = 0;
        if (result.score > 100) result.score = 100;
    }

    // Map score to Strength Level
    if (result.score <= 20) {
        result.strength = StrengthLevel::VeryWeak;
    } else if (result.score <= 40) {
        result.strength = StrengthLevel::Weak;
    } else if (result.score <= 60) {
        result.strength = StrengthLevel::Medium;
    } else if (result.score <= 80) {
        result.strength = StrengthLevel::Strong;
    } else {
        result.strength = StrengthLevel::VeryStrong;
    }

    // 7. Suggestions list
    if (password.length() < 12) {
        result.suggestions.push_back("Increase length to 12 or more characters (currently: " + std::to_string(password.length()) + ").");
    }
    if (!result.hasUpper) {
        result.suggestions.push_back("Add uppercase letters (A-Z) to increase character diversity.");
    }
    if (!result.hasLower) {
        result.suggestions.push_back("Add lowercase letters (a-z) to increase character diversity.");
    }
    if (!result.hasDigit) {
        result.suggestions.push_back("Add numbers (0-9) to increase complexity.");
    }
    if (!result.hasSpecial) {
        result.suggestions.push_back("Add special symbols (e.g. !, @, #, $, %) to make it harder to guess.");
    }
    if (result.hasRepeats) {
        result.suggestions.push_back("Avoid repeated character sequences (e.g. 'aaa').");
    }
    if (result.hasSeqNumbers || result.hasSeqAlphabets) {
        result.suggestions.push_back("Avoid predictable alphabetical/numerical sequences (e.g. 'abc', '123').");
    }
    if (result.hasKeyboardPatterns) {
        result.suggestions.push_back("Avoid sequential keyboard row layouts (e.g. 'qwerty', 'asdf').");
    }
    if (result.isCommon) {
        result.suggestions.push_back("This is a widely used common password. Choose a unique password.");
    } else if (result.containsDictWord) {
        result.suggestions.push_back("Avoid dictionary words as they are vulnerable to dictionary attacks.");
    }

    return result;
}

} // namespace PasswordChecker
