"use client";

import { useState } from "react";
import { generateReport } from "@/utils/api";

interface ReportExporterProps {
  data: any;
}

export default function ReportExporter({ data }: ReportExporterProps) {
  const [isExporting, setIsExporting] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);

  const exportMarkdown = async () => {
    setIsExporting(true);
    try {
      const markdown = generateMarkdownReport(data);
      downloadFile(markdown, `suigraph-report-${Date.now()}.md`, "text/markdown");
    } catch (error) {
      console.error("Markdown export failed:", error);
      alert("Failed to export markdown report");
    } finally {
      setIsExporting(false);
      setShowDropdown(false);
    }
  };

  const exportPDF = async () => {
    setIsExporting(true);
    try {
      // Create a comprehensive HTML report
      const htmlContent = generateHTMLReport(data);
      
      // Use browser's print functionality to generate PDF
      const printWindow = window.open("", "_blank");
      if (printWindow) {
        printWindow.document.write(htmlContent);
        printWindow.document.close();
        
        // Wait for content to load, then print
        printWindow.onload = () => {
          printWindow.print();
          printWindow.close();
        };
      }
    } catch (error) {
      console.error("PDF export failed:", error);
      alert("Failed to export PDF report");
    } finally {
      setIsExporting(false);
      setShowDropdown(false);
    }
  };

  const exportJSON = () => {
    setIsExporting(true);
    try {
      const jsonData = JSON.stringify(data, null, 2);
      downloadFile(jsonData, `suigraph-data-${Date.now()}.json`, "application/json");
    } catch (error) {
      console.error("JSON export failed:", error);
      alert("Failed to export JSON data");
    } finally {
      setIsExporting(false);
      setShowDropdown(false);
    }
  };

  const downloadFile = (content: string, filename: string, contentType: string) => {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const generateMarkdownReport = (data: any) => {
    const timestamp = new Date().toISOString();
    const vulnerabilities = data.vulnerabilities || [];
    
    let markdown = `# SuiGraph Security Analysis Report

**Generated:** ${new Date(timestamp).toLocaleString()}
**Analysis ID:** ${timestamp}

## Executive Summary

- **Modules Analyzed:** ${data.modules?.length || 0}
- **Functions Analyzed:** ${data.functions?.length || 0}
- **Total Vulnerabilities:** ${vulnerabilities.length}

### Vulnerability Breakdown by Severity
`;

    // Add severity breakdown
    const severityCounts = {
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length
    };

    markdown += `
| Severity | Count |
|----------|-------|
| High     | ${severityCounts.high} |
| Medium   | ${severityCounts.medium} |
| Low      | ${severityCounts.low} |

## Detailed Findings

`;

    // Add vulnerability details
    if (vulnerabilities.length > 0) {
      vulnerabilities.forEach((vuln, index) => {
        markdown += `
### ${index + 1}. ${vuln.name}

**Severity:** ${vuln.severity.toUpperCase()}  
**File:** ${vuln.file}  
**Line:** ${vuln.line}  
**Confidence:** ${vuln.confidence}

**Description:** ${vuln.description}

**Code Context:**
\`\`\`move
${vuln.code}
\`\`\`

**Recommendation:** ${vuln.recommendation}

---
`;
      });
    } else {
      markdown += `No security vulnerabilities were detected in the analyzed smart contract(s).

`;
    }

    // Add module information
    markdown += `
## Module Analysis

`;

    if (data.modules && data.modules.length > 0) {
      data.modules.forEach((module, index) => {
        markdown += `
### ${index + 1}. ${module.name}

- **Full Name:** ${module.fullName || module.name}
- **Address:** ${module.address || 'Not specified'}
- **File:** ${module.file}

`;
      });
    }

    // Add function analysis
    markdown += `
## Function Analysis

`;

    if (data.functions && data.functions.length > 0) {
      data.functions.forEach((func, index) => {
        markdown += `
### ${index + 1}. ${func.name}

- **Module:** ${func.module}
- **Visibility:** ${func.visibility}
- **Entry Function:** ${func.isEntry ? 'Yes' : 'No'}
- **File:** ${func.file}
- **Line:** ${func.line}

`;
      });
    }

    markdown += `
## Risk Assessment

Based on the analysis, the overall risk level is determined by the highest severity vulnerability found:

`;

    if (severityCounts.high > 0) {
      markdown += `**🔴 HIGH RISK** - Critical vulnerabilities require immediate attention.`;
    } else if (severityCounts.medium > 0) {
      markdown += `**🟡 MEDIUM RISK** - Some security concerns should be addressed.`;
    } else if (severityCounts.low > 0) {
      markdown += `**🟢 LOW RISK** - Minor issues detected, consider addressing for best practices.`;
    } else {
      markdown += `**✅ SECURE** - No significant security issues detected.`;
    }

    markdown += `

## Methodology

This analysis was performed using SuiGraph's static analysis engine, which examines Move smart contract source code for common security vulnerabilities and anti-patterns. The tool checks for:

- Unrestricted public entry functions
- Unchecked coin transfers
- Mutable shared object access patterns
- Authority and capability misuse
- Missing error handling
- External module dependencies

## Disclaimer

This automated analysis should be considered as a first-pass security review. Manual code review by security experts is recommended for production smart contracts.

---
*Report generated by SuiGraph v1.0*
`;

    return markdown;
  };

  const generateHTMLReport = (data: any) => {
    const markdownContent = generateMarkdownReport(data);
    
    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SuiGraph Security Analysis Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 { color: #2563eb; }
        h1 { border-bottom: 3px solid #2563eb; padding-bottom: 10px; }
        h2 { border-bottom: 1px solid #e5e7eb; padding-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #d1d5db; padding: 8px 12px; text-align: left; }
        th { background-color: #f3f4f6; font-weight: 600; }
        code { background: #f1f5f9; padding: 2px 4px; border-radius: 3px; font-family: 'Monaco', 'Menlo', monospace; }
        pre { background: #1f2937; color: #10b981; padding: 15px; border-radius: 5px; overflow-x: auto; }
        pre code { background: none; color: inherit; }
        .severity-high { color: #dc2626; font-weight: bold; }
        .severity-medium { color: #d97706; font-weight: bold; }
        .severity-low { color: #2563eb; font-weight: bold; }
        hr { border: none; border-top: 1px solid #e5e7eb; margin: 30px 0; }
        @media print {
            body { margin: 0; font-size: 12px; }
            h1 { font-size: 18px; }
            h2 { font-size: 16px; }
            h3 { font-size: 14px; }
        }
    </style>
</head>
<body>
    <div id="content">${markdownToHTML(markdownContent)}</div>
</body>
</html>`;
  };

  const markdownToHTML = (markdown: string) => {
    // Simple markdown to HTML conversion
    return markdown
      .replace(/^# (.*$)/gm, '<h1>$1</h1>')
      .replace(/^## (.*$)/gm, '<h2>$1</h2>')
      .replace(/^### (.*$)/gm, '<h3>$1</h3>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/^\| (.*) \|$/gm, '<tr><td>$1</td></tr>')
      .replace(/^\|----.*\|$/gm, '')
      .replace(/```move\n(.*?)\n```/gs, '<pre><code>$1</code></pre>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/^---$/gm, '<hr>')
      .replace(/\n\n/g, '</p><p>')
      .replace(/^(?!<h|<t|<p|<u|<o|<h|<d)(.+)/gm, '<p>$1</p>')
      .replace(/<p><\/p>/g, '')
      .replace(/HIGH RISK/g, '<span class="severity-high">HIGH RISK</span>')
      .replace(/MEDIUM RISK/g, '<span class="severity-medium">MEDIUM RISK</span>')
      .replace(/LOW RISK/g, '<span class="severity-low">LOW RISK</span>');
  };

  return (
    <div className="relative">
      <button
        onClick={() => setShowDropdown(!showDropdown)}
        disabled={isExporting}
        className="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
      >
        {isExporting ? (
          <>
            <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-gray-500" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Exporting...
          </>
        ) : (
          <>
            <svg className="-ml-1 mr-2 h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Export Report
            <svg className="-mr-1 ml-2 h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
            </svg>
          </>
        )}
      </button>

      {/* Dropdown Menu */}
      {showDropdown && (
        <div className="absolute right-0 mt-2 w-56 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-50">
          <div className="py-1" role="menu" aria-orientation="vertical">
            <button
              onClick={exportPDF}
              className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
              role="menuitem"
            >
              <svg className="mr-3 h-4 w-4 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z" clipRule="evenodd" />
              </svg>
              Export as PDF
            </button>
            <button
              onClick={exportMarkdown}
              className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
              role="menuitem"
            >
              <svg className="mr-3 h-4 w-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Export as Markdown
            </button>
            <button
              onClick={exportJSON}
              className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
              role="menuitem"
            >
              <svg className="mr-3 h-4 w-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
              </svg>
              Export as JSON
            </button>
          </div>
        </div>
      )}

      {/* Click outside to close */}
      {showDropdown && (
        <div 
          className="fixed inset-0 z-40"
          onClick={() => setShowDropdown(false)}
        />
      )}
    </div>
  );
}