#pragma once
#include <string>
#include <unordered_set>
#include <vector>

namespace PasswordChecker {

class PasswordDictionary {
private:
    std::unordered_set<std::string> dictionary;
    std::vector<std::string> orderedWords; // Retains ordering for search heuristics
    bool loaded = false;

public:
    PasswordDictionary() = default;

    // Loads the dictionary from a specific file path (offline text file).
    // Returns true on success, false on failure.
    bool loadFromFile(const std::string& filepath);

    // Checks if the password itself is in the common passwords list (case-insensitive).
    bool isCommonPassword(const std::string& password) const;

    // Checks if the password contains any word from the dictionary of length >= 4 as a substring.
    // If found, returns true and sets 'matchedWord' to the word that matched.
    bool containsDictionaryWord(const std::string& password, std::string& matchedWord) const;

    // Status queries
    bool isLoaded() const { return loaded; }
    size_t size() const { return dictionary.size(); }
};

} // namespace PasswordChecker
