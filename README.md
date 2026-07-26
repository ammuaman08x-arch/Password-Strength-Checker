INTERID: CT-5160
FULL NAME: MD AMAN UL HAQ
NO.OF WEEKS: 1
PROJECT NAME: PASSWORD STRENGTH CHECKER
PROJECT SCOPE: The Password Strength Checker is a desktop-based cybersecurity application developed in C++ using Dear ImGui. The project analyzes passwords based on security parameters such as length, character diversity (uppercase, lowercase, numbers, and special characters), dictionary word detection, repeated and sequential pattern detection, keyboard pattern recognition, entropy calculation, and estimated password crack time. It provides a strength score, visual feedback, and recommendations to help users create stronger passwords. The application works completely offline, making it suitable for educational purposes, cybersecurity awareness, and secure password evaluation without transmitting sensitive information over the internet.




# Password Strength Checker (C++ & Dear ImGui)

A professional, offline, desktop security application designed to analyze password complexity and evaluate vulnerability against standard cyber attacks. Developed as a **B.Tech Cyber Security** project, it demonstrates key cryptography and information security concepts through a modern, responsive user interface.

---

## Project Overview

This application evaluates user-entered passwords against several cybersecurity rules and metrics. It computes real-time security scores, estimates Shannon entropy, calculates approximate offline cracking times under a hypothetical high-performance brute-force setup, and lists detailed recommendations for structural improvement.

---

## Features

### 1. Advanced Password Analysis
- **Length Check**: Assesses if the password meets modern length recommendations ($\ge 12$ characters).
- **Character Diversity**: Checks for uppercase, lowercase, numbers, and special symbols.
- **Sequential Pattern Detection**: Detects sequential numbers (e.g. `123`, `987`) and letters (e.g. `abc`, `xyz`), which are easily guessed by dictionary-based rule processors.
- **Repetitive Key Scans**: Flags runs of repeating characters (e.g. `aaa`, `1111`) that inflate length without adding cryptographic strength.
- **Keyboard Layout Detection**: Identifies adjacent keyboard sequences (e.g. `qwerty`, `asdf`, `zxcv`) across QWERTY layout rows.
- **Offline Dictionary Lookup**: Performs fast lookups against a local file containing common/weak passwords (like `admin`, `letmein`, `password`) and searches for dictionary words embedded as substrings.

### 2. Cryptographic & Analytical Metrics
- **Shannon Entropy**: Computes password information density in bits ($E = L \times \log_2(R)$), representing the exact complexity of the character space.
- **Crack Time Estimation**: Translates the entropy value into a human-readable duration (seconds, hours, years, centuries, etc.) assuming an average offline brute-force guessing rate of $10^{10}$ attempts/second.
- **Categorized Scoring (0–100)**: Maps security to distinct tiers:
  - `0–20`: Very Weak (Red)
  - `21–40`: Weak (Orange)
  - `41–60`: Medium (Yellow)
  - `61–80`: Strong (Light Green)
  - `81–100`: Very Strong (Green)

### 3. Generator & Productivity Tools
- **Secure Password Generator**: Generates strong, random passwords using standard C++ random engines (`std::mt19937`). Guarantees that selected character types (lowercase, uppercase, numbers, symbols) are included in the generated output.
- **Session History Panel**: Retains a runtime history of analyzed passwords and their scores. Click on any historical record to reload its stats.
- **Dynamic Report Exporter**: Formats analysis metrics into a clean text document and exports it locally as `PasswordReport.txt` (with password values masked for security).
- **Dark/Light Theme Toggle**: Swap between a Slate Dark Mode and a Clean Light Mode.
- **Live Typing Analysis**: Analyzes and updates GUI components in real time as you type.

---

## Technologies Used

- **Language**: Modern C++ (C++17)
- **GUI Engine**: Dear ImGui (v1.90.5)
- **Windowing & Input**: GLFW (v3.3.8)
- **Rendering API**: OpenGL 3.0 (with built-in shader headers)
- **Build System**: CMake (minimum version 3.14)
- **Libraries Used**: Standard C++ Library only (`<algorithm>`, `<cmath>`, `<random>`, `<vector>`, `<unordered_set>`)

---

## Folder Structure

```
PasswordStrengthChecker/
├── assets/
│   └── common_passwords.txt           # Offline dictionary of weak passwords/dictionary words
├── include/
│   ├── PasswordChecker.h              # Orchestrates the overall evaluation API
│   ├── EntropyCalculator.h            # Handles Shannon entropy & character pool calculations
│   ├── PatternDetector.h              # Scans for keyboard sequences, alphabetics, and runs
│   ├── PasswordDictionary.h           # Offline word set scanner and substring matcher
│   ├── ReportGenerator.h              # Formats and exports text files
│   └── GUITheme.h                     # Holds the ImGui Dark/Light style palettes
├── src/
│   ├── main.cpp                       # App entry point, GLFW setup, & ImGui render loop
│   ├── PasswordChecker.cpp            # Password scoring and recommendation logic
│   ├── EntropyCalculator.cpp          # Shannon entropy and charset pool implementation
│   ├── PatternDetector.cpp            # Repeating/sequential pattern detection rules
│   ├── PasswordDictionary.cpp         # Word set loading & case-insensitive search logic
│   └── ReportGenerator.cpp            # Text formatting and masking functions
├── CMakeLists.txt                     # Build configuration file
├── ARCHITECTURE.md                    # Technical architecture & formulas documentation
└── README.md                          # Project documentation (this file)
```


---

## Build & Run Instructions

Ensure you have a modern C++ compiler (Visual Studio 2017+ on Windows, GCC 8+ on Linux/MinGW) and CMake installed.

### 1. Build using command line (CMake)
Open your terminal inside the project directory:

```bash
# Generate build configuration
cmake -B build -S .

# Build the binary in Release mode
cmake --build build --config Release
```

### 2. Run the application
Once the build completes, the executable and the assets directory will be copied to `build/Release/`.
Run it using:

```bash
# Run the executable
./build/Release/PasswordStrengthChecker.exe
```

---

## Cybersecurity Concepts Demonstrated

During a viva, this project helps demonstrate practical implementations of:
1. **Brute Force Key Space Complexity**: How adding length versus widening the character pool size affects the total combinations ($R^L$) exponentially.
2. **Shannon Entropy (Information Theory)**: Using entropy to quantify password randomness. The formula $E = L \log_2 R$ shows why random 12-character passwords can be stronger than longer, predictable sentences.
3. **Dictionary & Substring Attacks**: Showcasing how dictionary lookups instantly neutralize passwords regardless of their theoretical entropy (e.g. `password123`).
4. **Pattern & Keyboard Adjacency Heuristics**: Implementing keyboard coordinates checking to detect simple physical finger-sliding paths which are heavily prioritized in modern rule-based cracking dictionaries (e.g., John the Ripper / Hashcat rulesets).
5. **Secure Random Number Generation**: Using `std::random_device` and Mersenne Twister engine (`std::mt19937`) to avoid predictable seeding in random password generation.

---

## Learning Outcomes

- Structuring multi-file C++ systems using namespaces and header-only interfaces.
- Integrating external open-source projects using CMake's modern `FetchContent` framework.
- Managing low-level graphics contexts (OpenGL) and window bindings (GLFW) for immediate-mode GUI layouts.
- Developing robust user input pipelines and live-state synchronization.
