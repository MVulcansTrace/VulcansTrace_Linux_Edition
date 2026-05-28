#!/bin/bash

# Code Coverage Analysis Script for VulcansTrace Linux Edition
# Runs tests with coverage collection and generates an HTML report

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_PROJECT="$PROJECT_ROOT/VulcansTrace.Linux.Tests/VulcansTrace.Linux.Tests.csproj"
RESULTS_DIR="$PROJECT_ROOT/TestResults"
COVERAGE_DIR="$RESULTS_DIR/CoverageReport"
TEST_RESULTS_DIR="$PROJECT_ROOT/VulcansTrace.Linux.Tests/TestResults"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║    VulcansTrace Linux Edition - Code Coverage Analysis    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Clean previous results
echo "🧹 Cleaning previous coverage results..."
rm -rf "$COVERAGE_DIR"
rm -rf "$TEST_RESULTS_DIR"

# Run tests with coverage
echo ""
echo "🧪 Running tests with coverage collection..."
dotnet test "$TEST_PROJECT" \
    --verbosity quiet \
    --collect:"XPlat Code Coverage"

# Find the latest coverage XML (coverlet produces Cobertura format)
LATEST_COVERAGE=$(find "$TEST_RESULTS_DIR" -name "coverage.cobertura.xml" -type f | head -1)

if [ -z "$LATEST_COVERAGE" ]; then
    echo "❌ Error: Coverage file not generated"
    exit 1
fi

echo ""
echo "📊 Generating HTML coverage report..."

# Generate report using dotnet-reportgenerator
reportgenerator \
    "-reports:$LATEST_COVERAGE" \
    "-targetdir:$COVERAGE_DIR" \
    "-reporttypes:Html;TextSummary" \
    "-assemblyfilters:+VulcansTrace.*"

# Print summary from the text report
SUMMARY_FILE="$COVERAGE_DIR/Summary.txt"
if [ -f "$SUMMARY_FILE" ]; then
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                  COVERAGE SUMMARY                         ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    cat "$SUMMARY_FILE"
fi

echo ""
echo "✅ Coverage analysis complete!"
echo ""
echo "To view the report:"
echo "  open $COVERAGE_DIR/index.html"
echo ""
