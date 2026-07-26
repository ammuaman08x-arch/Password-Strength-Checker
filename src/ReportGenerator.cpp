#include "ReportGenerator.h"
#include "PasswordChecker.h"
#include <fstream>
#include <sstream>
#include <iomanip>

namespace PasswordChecker {

// Helper to mask password for the printed report (e.g. "p*****d")
static std::string maskPassword(const std::string& pwd) {
    if (pwd.empty()) return "";
    if (pwd.length() <= 2) return pwd.substr(0, 1) + "*";
    
    std::string masked = pwd.substr(0, 1);
    masked += std::string(pwd.length() - 2, '*');
    masked += pwd.substr(pwd.length() - 1, 1);
    return masked;
}

std::string ReportGenerator::generateTextReport(const AnalysisResult& result) {
    std::stringstream ss;
    ss << "==================================================\n";
    ss << "         PASSWORD STRENGTH ANALYSIS REPORT        \n";
    ss << "==================================================\n\n";
    
    ss << "Password Details:\n";
    ss << "  Masked Password : " << maskPassword(result.password) << "\n";
    ss << "  Length          : " << result.password.length() << " characters\n\n";

    ss << "Overall Strength Metrics:\n";
    ss << "  Score           : " << result.score << " / 100\n";
    ss << "  Strength Level  : " << PasswordChecker::getStrengthLevelName(result.strength) << "\n";
    ss << "  Shannon Entropy : " << std::fixed << std::setprecision(2) << result.entropy << " bits\n";
    ss << "  Est. Crack Time : " << result.crackTimeStr << "\n\n";

    ss << "Security Checklist:\n";
    ss << "  [ " << (result.hasMinLength ? "PASS" : "FAIL") << " ] Length (minimum 12 characters)\n";
    ss << "  [ " << (result.hasUpper ? "PASS" : "FAIL") << " ] Contains uppercase letters (A-Z)\n";
    ss << "  [ " << (result.hasLower ? "PASS" : "FAIL") << " ] Contains lowercase letters (a-z)\n";
    ss << "  [ " << (result.hasDigit ? "PASS" : "FAIL") << " ] Contains numbers (0-9)\n";
    ss << "  [ " << (result.hasSpecial ? "PASS" : "FAIL") << " ] Contains special symbols\n";
    ss << "  [ " << (result.isCommon ? "FAIL" : "PASS") << " ] Common / Weak password check\n";
    ss << "  [ " << (result.containsDictWord ? "FAIL" : "PASS") << " ] Dictionary word substring check\n";
    ss << "  [ " << (result.hasRepeats ? "FAIL" : "PASS") << " ] Repeated character check\n";
    ss << "  [ " << (result.hasKeyboardPatterns ? "FAIL" : "PASS") << " ] Keyboard pattern check\n";
    ss << "  [ " << (result.hasSeqNumbers ? "FAIL" : "PASS") << " ] Sequential numbers check\n";
    ss << "  [ " << (result.hasSeqAlphabets ? "FAIL" : "PASS") << " ] Sequential alphabets check\n\n";

    if (result.isCommon || result.containsDictWord || result.hasRepeats || 
        result.hasKeyboardPatterns || result.hasSeqNumbers || result.hasSeqAlphabets) {
        ss << "Pattern Analysis Details:\n";
        if (result.isCommon) {
            ss << "  - Flagged as a known common/weak password.\n";
        }
        if (result.containsDictWord) {
            ss << "  - " << result.dictWordDetails << "\n";
        }
        if (result.hasRepeats) {
            ss << "  - " << result.repeatsDetails << "\n";
        }
        if (result.hasKeyboardPatterns) {
            ss << "  - " << result.keyboardPatternsDetails << "\n";
        }
        if (result.hasSeqNumbers) {
            ss << "  - " << result.seqNumbersDetails << "\n";
        }
        if (result.hasSeqAlphabets) {
            ss << "  - " << result.seqAlphabetsDetails << "\n";
        }
        ss << "\n";
    }

    ss << "Improvement Suggestions:\n";
    if (result.suggestions.empty()) {
        ss << "  - Excellent job! No changes needed. Keep this password safe.\n";
    } else {
        for (const auto& suggestion : result.suggestions) {
            ss << "  - " << suggestion << "\n";
        }
    }
    
    ss << "\n==================================================\n";
    ss << "Educational Disclaimer:\n";
    ss << "This report is generated for academic and educational purposes.\n";
    ss << "Calculated entropy is based on information theory formulas.\n";
    ss << "Estimated crack times assume a generic high-speed brute-force attack.\n";
    ss << "==================================================\n";

    return ss.str();
}

bool ReportGenerator::exportReportToFile(const std::string& filepath, const AnalysisResult& result) {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        return false;
    }
    file << generateTextReport(result);
    return true;
}

} // namespace PasswordChecker
