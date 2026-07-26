#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <fstream>

#include <GLFW/glfw3.h>
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include "PasswordChecker.h"
#include "PasswordDictionary.h"
#include "ReportGenerator.h"
#include "GUITheme.h"

// Helper to search for the offline common passwords list
static std::string locateDictionaryFile() {
    std::vector<std::string> searchPaths = {
        "assets/common_passwords.txt",
        "../assets/common_passwords.txt",
        "../../assets/common_passwords.txt",
        "build/assets/common_passwords.txt",
        "PasswordStrengthChecker/assets/common_passwords.txt"
    };

    for (const auto& path : searchPaths) {
        std::ifstream file(path);
        if (file.good()) {
            return path;
        }
    }
    return "";
}

// Secure password generator that guarantees inclusions of active character classes
static std::string generateSecurePassword(int length, bool includeLower, bool includeUpper, bool includeDigits, bool includeSymbols) {
    if (length < 4) length = 4;
    
    std::string lowerSet = "abcdefghijklmnopqrstuvwxyz";
    std::string upperSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string digitSet = "0123456789";
    std::string symbolSet = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

    std::string combinedPool = "";
    std::string guaranteedChars = "";

    // Set up random devices
    static std::random_device rd;
    static std::mt19937 gen(rd());

    if (includeLower) {
        combinedPool += lowerSet;
        std::uniform_int_distribution<> dis(0, static_cast<int>(lowerSet.size()) - 1);
        guaranteedChars += lowerSet[dis(gen)];
    }
    if (includeUpper) {
        combinedPool += upperSet;
        std::uniform_int_distribution<> dis(0, static_cast<int>(upperSet.size()) - 1);
        guaranteedChars += upperSet[dis(gen)];
    }
    if (includeDigits) {
        combinedPool += digitSet;
        std::uniform_int_distribution<> dis(0, static_cast<int>(digitSet.size()) - 1);
        guaranteedChars += digitSet[dis(gen)];
    }
    if (includeSymbols) {
        combinedPool += symbolSet;
        std::uniform_int_distribution<> dis(0, static_cast<int>(symbolSet.size()) - 1);
        guaranteedChars += symbolSet[dis(gen)];
    }

    if (combinedPool.empty()) {
        return "";
    }

    std::string result = guaranteedChars;
    int remaining = length - static_cast<int>(result.length());
    std::uniform_int_distribution<> poolDis(0, static_cast<int>(combinedPool.size()) - 1);

    for (int i = 0; i < remaining; ++i) {
        result += combinedPool[poolDis(gen)];
    }

    // Shuffle the final password to mix the guaranteed characters
    std::shuffle(result.begin(), result.end(), gen);
    return result;
}

// Utility function to draw colored ticks [v] or crosses [x]
static void renderChecklistItem(bool conditionSatisfied, const char* label, bool reverseLogic = false) {
    bool isPassing = reverseLogic ? !conditionSatisfied : conditionSatisfied;
    if (isPassing) {
        ImGui::TextColored(ImVec4(0.25f, 0.8f, 0.25f, 1.0f), "[v]"); // Green Tick
    } else {
        ImGui::TextColored(ImVec4(0.85f, 0.25f, 0.25f, 1.0f), "[x]"); // Red Cross
    }
    ImGui::SameLine();
    ImGui::Text("%s", label);
}

static void glfw_error_callback(int error, const char* description) {
    std::cerr << "GLFW Error " << error << ": " << description << std::endl;
}

int main(int, char**) {
    // 1. Setup GLFW
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        return 1;
    }

    // Setup OpenGL context version
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // Create window
    GLFWwindow* window = glfwCreateWindow(1000, 720, "Password Strength Checker", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    // 2. Initialize Dear ImGui Context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Apply Dark Theme by default
    bool isDarkMode = true;
    PasswordChecker::GUITheme::applyDarkTheme();

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // 3. Load Offline Dictionary
    PasswordChecker::PasswordDictionary dictionary;
    std::string dictPath = locateDictionaryFile();
    bool dictLoaded = false;
    if (!dictPath.empty()) {
        dictLoaded = dictionary.loadFromFile(dictPath);
    }

    // 4. GUI State variables
    char pwdInputBuffer[128] = "";
    std::string lastAnalyzedPwd = "";
    PasswordChecker::AnalysisResult currentAnalysis;
    
    bool showPassword = false;
    std::vector<std::pair<std::string, PasswordChecker::AnalysisResult>> history;
    
    // Export state
    std::string exportMessage = "";
    bool exportSuccess = false;

    // Generator state
    int genLength = 16;
    bool genLower = true;
    bool genUpper = true;
    bool genDigits = true;
    bool genSymbols = true;
    char genOutputBuffer[128] = "";

    // 5. Main loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        // Start Dear ImGui Frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Apply theme if changed
        if (isDarkMode) {
            PasswordChecker::GUITheme::applyDarkTheme();
        } else {
            PasswordChecker::GUITheme::applyLightTheme();
        }

        // Cover the entire application screen with our GUI
        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
        ImGui::Begin("Main Window Panel", nullptr, 
                     ImGuiWindowFlags_NoDecoration | 
                     ImGuiWindowFlags_NoMove | 
                     ImGuiWindowFlags_NoResize | 
                     ImGuiWindowFlags_NoSavedSettings);

        // --- TOP TITLE BAR ---
        ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "Password Strength Checker");
        ImGui::SameLine();
        ImGui::TextDisabled(" |  B.Tech Cyber Security Project");
        
        // Theme Toggle Placement
        float toggleOffset = ImGui::GetWindowWidth() - 150.0f;
        if (toggleOffset > 400.0f) {
            ImGui::SameLine(toggleOffset);
            if (ImGui::Checkbox(isDarkMode ? "Dark Theme" : "Light Theme", &isDarkMode)) {
                // Toggles theme state next frame
            }
        }

        ImGui::Separator();
        ImGui::Spacing();

        // --- SPLIT LAYOUT IN 2 COLUMNS ---
        // Left Column (width ~58% for analyzer input & checklist)
        // Right Column (width ~40% for score stats, generator, and history)
        float availableWidth = ImGui::GetContentRegionAvail().x;
        float leftWidth = availableWidth * 0.58f;
        float rightWidth = availableWidth * 0.40f;

        ImGui::BeginGroup(); // Left Column Group
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 4.0f);
        
        // --- 1. PASSWORD INPUT BLOCK ---
        ImGui::BeginChild("InputBlock", ImVec2(leftWidth, 120), true);
        ImGui::Text("Enter Password for Analysis:");
        ImGui::Spacing();

        // Mask/Unmask input field
        ImGuiInputTextFlags inputFlags = ImGuiInputTextFlags_None;
        if (!showPassword) {
            inputFlags |= ImGuiInputTextFlags_Password;
        }

        ImGui::PushItemWidth(-1.0f);
        if (ImGui::InputText("##pwd_field", pwdInputBuffer, IM_ARRAYSIZE(pwdInputBuffer), inputFlags)) {
            // Live scanning trigger
            std::string currentPwdStr = pwdInputBuffer;
            if (currentPwdStr != lastAnalyzedPwd) {
                currentAnalysis = PasswordChecker::PasswordChecker::analyze(currentPwdStr, dictionary);
                lastAnalyzedPwd = currentPwdStr;
                exportMessage = ""; // Reset export state on changes
            }
        }
        ImGui::PopItemWidth();
        ImGui::Spacing();

        ImGui::Checkbox("Show Password", &showPassword);
        ImGui::SameLine(ImGui::GetWindowWidth() - 170.0f);
        if (ImGui::Button("Save to History", ImVec2(150, 0))) {
            std::string pwd = pwdInputBuffer;
            if (!pwd.empty()) {
                // Check if already the last item in history to prevent duplicates
                bool duplicate = false;
                if (!history.empty() && history.back().first == pwd) {
                    duplicate = true;
                }
                if (!duplicate) {
                    history.push_back({pwd, currentAnalysis});
                    if (history.size() > 8) {
                        history.erase(history.begin());
                    }
                }
            }
        }
        ImGui::EndChild();

        ImGui::Spacing();

        // --- 2. EVALUATION CHECKLIST ---
        ImGui::BeginChild("ChecklistBlock", ImVec2(leftWidth, 230), true);
        ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "Security Rules Checklist");
        ImGui::Separator();
        ImGui::Spacing();

        // Left split list of checklist
        float colWidth = (leftWidth - 20.0f) / 2.0f;
        ImGui::Columns(2, "checklist_cols", false);
        ImGui::SetColumnWidth(0, colWidth);
        ImGui::SetColumnWidth(1, colWidth);

        // Core strength criteria
        renderChecklistItem(currentAnalysis.hasMinLength, "Length (>= 12 characters)");
        renderChecklistItem(currentAnalysis.hasUpper, "Uppercase Letters (A-Z)");
        renderChecklistItem(currentAnalysis.hasLower, "Lowercase Letters (a-z)");
        renderChecklistItem(currentAnalysis.hasDigit, "Numeric Digits (0-9)");
        renderChecklistItem(currentAnalysis.hasSpecial, "Special Symbols (!@#$%)");

        ImGui::NextColumn();

        // Weak patterns criteria
        renderChecklistItem(currentAnalysis.isCommon, "No Common Password Match", true);
        renderChecklistItem(currentAnalysis.containsDictWord, "No Dictionary Substring", true);
        renderChecklistItem(currentAnalysis.hasRepeats, "No Repeated Characters", true);
        renderChecklistItem(currentAnalysis.hasKeyboardPatterns, "No Keyboard Patterns", true);
        renderChecklistItem(currentAnalysis.hasSeqNumbers || currentAnalysis.hasSeqAlphabets, "No Sequential Runs", true);

        ImGui::Columns(1);
        ImGui::Spacing();
        ImGui::Separator();
        
        // Dictionary Status Indicator (Viva friendly)
        if (dictLoaded) {
            ImGui::TextColored(ImVec4(0.3f, 0.8f, 0.3f, 1.0f), "Offline Dictionary Active (%d words loaded)", static_cast<int>(dictionary.size()));
        } else {
            ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "Offline Dictionary Error: assets/common_passwords.txt missing!");
        }
        ImGui::EndChild();

        ImGui::Spacing();

        // --- 3. RECOMMENDATIONS & SUGGESTIONS ---
        ImGui::BeginChild("SuggestionsBlock", ImVec2(leftWidth, 220), true);
        ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "Actionable Suggestions");
        ImGui::Separator();
        ImGui::Spacing();

        if (currentAnalysis.suggestions.empty() && !lastAnalyzedPwd.empty()) {
            ImGui::TextColored(ImVec4(0.25f, 0.8f, 0.25f, 1.0f), "[Excellent] This password adheres to all cybersecurity rules!");
        } else if (lastAnalyzedPwd.empty()) {
            ImGui::TextDisabled("Enter a password above to generate security recommendations.");
        } else {
            ImGui::BeginChild("SuggestionsScroll", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);
            for (const auto& suggestion : currentAnalysis.suggestions) {
                ImGui::BulletText("%s", suggestion.c_str());
            }
            ImGui::EndChild();
        }
        ImGui::EndChild();

        ImGui::PopStyleVar();
        ImGui::EndGroup(); // End Left Column Group

        ImGui::SameLine(leftWidth + availableWidth * 0.02f); // Spacing gap between columns

        ImGui::BeginGroup(); // Right Column Group
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 4.0f);

        // --- 4. OVERALL STRENGTH STATS ---
        ImGui::BeginChild("StatsBlock", ImVec2(rightWidth, 220), true);
        ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "Overall Security Strength");
        ImGui::Separator();
        ImGui::Spacing();

        // Progress bar color based on strength score
        ImVec4 barColor;
        if (currentAnalysis.score <= 20) {
            barColor = ImVec4(0.85f, 0.25f, 0.25f, 1.0f); // Red
        } else if (currentAnalysis.score <= 40) {
            barColor = ImVec4(0.90f, 0.50f, 0.15f, 1.0f); // Orange
        } else if (currentAnalysis.score <= 60) {
            barColor = ImVec4(0.90f, 0.80f, 0.20f, 1.0f); // Yellow
        } else if (currentAnalysis.score <= 80) {
            barColor = ImVec4(0.50f, 0.85f, 0.30f, 1.0f); // Light Green
        } else {
            barColor = ImVec4(0.25f, 0.80f, 0.25f, 1.0f); // Green
        }

        // Display Score progress bar
        float fraction = static_cast<float>(currentAnalysis.score) / 100.0f;
        std::string scoreOverlay = std::to_string(currentAnalysis.score) + " / 100";
        
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, barColor);
        ImGui::ProgressBar(fraction, ImVec2(-1.0f, 25.0f), scoreOverlay.c_str());
        ImGui::PopStyleColor();
        ImGui::Spacing();

        // Grid of security results
        ImGui::Text("Strength Level:");
        ImGui::SameLine(130);
        ImGui::TextColored(barColor, "%s", PasswordChecker::PasswordChecker::getStrengthLevelName(currentAnalysis.strength).c_str());

        ImGui::Text("Shannon Entropy:");
        ImGui::SameLine(130);
        ImGui::Text("%.2f bits", currentAnalysis.entropy);

        ImGui::Text("Est. Crack Time:");
        ImGui::SameLine(130);
        ImGui::TextColored(ImVec4(0.9f, 0.8f, 0.5f, 1.0f), "%s", currentAnalysis.crackTimeStr.c_str());

        ImGui::Spacing();
        ImGui::Separator();
        
        // Export Analysis Report to File Button
        if (ImGui::Button("Export Analysis Report (.txt)", ImVec2(-1.0f, 0))) {
            if (lastAnalyzedPwd.empty()) {
                exportMessage = "Error: Input is empty!";
                exportSuccess = false;
            } else {
                std::string path = "PasswordReport.txt";
                if (PasswordChecker::ReportGenerator::exportReportToFile(path, currentAnalysis)) {
                    exportMessage = "Report exported to 'PasswordReport.txt'!";
                    exportSuccess = true;
                } else {
                    exportMessage = "Error exporting report.";
                    exportSuccess = false;
                }
            }
        }

        if (!exportMessage.empty()) {
            if (exportSuccess) {
                ImGui::TextColored(ImVec4(0.3f, 0.8f, 0.3f, 1.0f), "%s", exportMessage.c_str());
            } else {
                ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "%s", exportMessage.c_str());
            }
        }
        ImGui::EndChild();

        ImGui::Spacing();

        // --- 5. PASSWORD GENERATOR BLOCK ---
        ImGui::BeginChild("GeneratorBlock", ImVec2(rightWidth, 230), true);
        ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "Password Generator");
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::PushItemWidth(120);
        ImGui::SliderInt("Length", &genLength, 6, 32);
        ImGui::PopItemWidth();

        ImGui::Columns(2, "gen_cols", false);
        ImGui::Checkbox("a-z", &genLower);
        ImGui::Checkbox("A-Z", &genUpper);
        ImGui::NextColumn();
        ImGui::Checkbox("0-9", &genDigits);
        ImGui::Checkbox("!@#$", &genSymbols);
        ImGui::Columns(1);
        ImGui::Spacing();

        if (ImGui::Button("Generate Password", ImVec2(150, 0))) {
            std::string generated = generateSecurePassword(genLength, genLower, genUpper, genDigits, genSymbols);
            snprintf(genOutputBuffer, sizeof(genOutputBuffer), "%s", generated.c_str());
        }
        
        ImGui::SameLine();

        if (ImGui::Button("Copy", ImVec2(60, 0))) {
            if (strlen(genOutputBuffer) > 0) {
                ImGui::SetClipboardText(genOutputBuffer);
            }
        }

        ImGui::Spacing();
        ImGui::PushItemWidth(-1.0f);
        ImGui::InputText("##generated_output", genOutputBuffer, IM_ARRAYSIZE(genOutputBuffer), ImGuiInputTextFlags_ReadOnly);
        ImGui::PopItemWidth();
        ImGui::EndChild();

        ImGui::Spacing();

        // --- 6. RUNTIME HISTORY LIST ---
        ImGui::BeginChild("HistoryBlock", ImVec2(rightWidth, 120), true);
        ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "Session History");
        ImGui::Separator();
        ImGui::Spacing();

        if (history.empty()) {
            ImGui::TextDisabled("No passwords saved yet.");
        } else {
            ImGui::BeginChild("HistoryScroll", ImVec2(0, 0), false);
            for (size_t i = 0; i < history.size(); ++i) {
                std::string label = "Score " + std::to_string(history[i].second.score) + " | " + 
                                    PasswordChecker::PasswordChecker::getStrengthLevelName(history[i].second.strength);
                
                // Clicking on a history line loads it back into the input buffer
                if (ImGui::Selectable(label.c_str())) {
                    snprintf(pwdInputBuffer, sizeof(pwdInputBuffer), "%s", history[i].first.c_str());
                    currentAnalysis = history[i].second;
                    lastAnalyzedPwd = history[i].first;
                    exportMessage = ""; // Reset export state
                }
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Click to load: %s", history[i].first.c_str());
                }
            }
            ImGui::EndChild();
        }
        ImGui::EndChild();

        ImGui::PopStyleVar();
        ImGui::EndGroup(); // End Right Column Group

        ImGui::End(); // End Main Window Panel

        // Rendering execution
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.11f, 0.11f, 0.14f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // Cleanup resources
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
