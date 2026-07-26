#include "PasswordDictionary.h"
#include <fstream>
#include <algorithm>
#include <cctype>

namespace PasswordChecker {

// Helper to convert string to lowercase
static std::string toLowerStr(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return lower;
}

// Helper to trim leading/trailing spaces or CR/LF from string
static std::string trim(const std::string& str) {
    if (str.empty()) return str;
    size_t first = 0;
    size_t last = str.length() - 1;
    while (first < str.length() && (std::isspace(static_cast<unsigned char>(str[first])) || str[first] == '\r' || str[first] == '\n')) {
        first++;
    }
    while (last > first && (std::isspace(static_cast<unsigned char>(str[last])) || str[last] == '\r' || str[last] == '\n')) {
        last--;
    }
    return (first <= last) ? str.substr(first, last - first + 1) : "";
}

bool PasswordDictionary::loadFromFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        loaded = false;
        return false;
    }

    dictionary.clear();
    orderedWords.clear();

    std::string line;
    while (std::getline(file, line)) {
        std::string word = trim(line);
        if (!word.empty()) {
            std::string lowerWord = toLowerStr(word);
            if (dictionary.find(lowerWord) == dictionary.end()) {
                dictionary.insert(lowerWord);
                orderedWords.push_back(lowerWord);
            }
        }
    }

    // Sort orderedWords by length descending so that when searching for substrings, 
    // we prioritize matching the longest possible dictionary word first.
    std::sort(orderedWords.begin(), orderedWords.end(), [](const std::string& a, const std::string& b) {
        return a.length() > b.length();
    });

    loaded = true;
    return true;
}

bool PasswordDictionary::isCommonPassword(const std::string& password) const {
    if (!loaded || password.empty()) {
        return false;
    }
    std::string pwdLower = toLowerStr(password);
    return dictionary.find(pwdLower) != dictionary.end();
}

bool PasswordDictionary::containsDictionaryWord(const std::string& password, std::string& matchedWord) const {
    if (!loaded || password.empty()) {
        return false;
    }

    std::string pwdLower = toLowerStr(password);
    
    // Check if any loaded dictionary word (of length >= 4) is a substring of the password
    for (const auto& word : orderedWords) {
        if (word.length() >= 4 && pwdLower.find(word) != std::string::npos) {
            matchedWord = word;
            return true;
        }
    }

    return false;
}

} // namespace PasswordChecker
