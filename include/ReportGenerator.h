#pragma once
#include <string>

namespace PasswordChecker {

struct AnalysisResult; // Forward declaration

class ReportGenerator {
public:
    // Generates a comprehensive, clean text-based report based on the analysis result.
    static std::string generateTextReport(const AnalysisResult& result);

    // Writes the generated report to a physical text file.
    // Returns true on success, false on failure.
    static bool exportReportToFile(const std::string& filepath, const AnalysisResult& result);
};

} // namespace PasswordChecker
