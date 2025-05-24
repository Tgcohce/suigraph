"use client";

import { useState } from "react";
import UploadForm from "@/components/UploadForm";
import SuiscanInput from "@/components/SuiscanInput";
import EnhancedGraphViewer from "@/components/EnhancedGraphViewer";
import VulnerabilityPanel from "@/components/VulnerabilityPanel";
import ReportExporter from "@/components/ReportExporter";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { useTheme } from "@/contexts/ThemeContext";

export default function Home() {
  const [analysisData, setAnalysisData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("graph");
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-blue-50 to-indigo-50 dark:from-gray-950 dark:via-gray-900 dark:to-gray-950 transition-all duration-300">
      {/* Animated Background Pattern */}
      <div className="fixed inset-0 bg-grid-pattern opacity-30 dark:opacity-20 pointer-events-none" />
      
      {/* Header */}
      <header className="relative bg-white/80 dark:bg-gray-900/80 backdrop-blur-xl border-b border-gray-200/50 dark:border-gray-700/50 shadow-lg shadow-gray-900/5">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center space-x-4">
              {/* Logo */}
              <div className="flex items-center space-x-3">
                <div className="relative">
                  <div className="w-10 h-10 bg-gradient-to-br from-primary-500 to-accent-purple rounded-xl flex items-center justify-center shadow-lg">
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                    </svg>
                  </div>
                  <div className="absolute -top-1 -right-1 w-4 h-4 bg-accent-cyan rounded-full animate-pulse" />
                </div>
                <div>
                  <h1 className="text-3xl font-bold bg-gradient-to-r from-gray-900 to-gray-600 dark:from-white dark:to-gray-300 bg-clip-text text-transparent">
                    SuiGraph
                  </h1>
                  <p className="text-xs text-gray-500 dark:text-gray-400 -mt-1">Smart Contract Security</p>
                </div>
              </div>
              
              {/* Status Badge */}
              <div className="hidden sm:flex items-center space-x-2">
                <div className="w-2 h-2 bg-success-500 rounded-full animate-pulse" />
                <span className="text-sm text-gray-600 dark:text-gray-300 font-medium">
                  System Online
                </span>
              </div>
            </div>

            {/* Header Actions */}
            <div className="flex items-center space-x-4">
              {/* Theme Toggle */}
              <button
                onClick={toggleTheme}
                className="p-2 rounded-xl bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors duration-200 group"
                title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
              >
                {theme === 'light' ? (
                  <svg className="w-5 h-5 text-gray-600 group-hover:text-gray-900 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5 text-gray-300 group-hover:text-white transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                  </svg>
                )}
              </button>

              {/* Export Button */}
              {analysisData && (
                <ReportExporter data={analysisData} />
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Input Panel */}
          <div className="lg:col-span-1 space-y-6">
            <div className="bg-white/90 dark:bg-gray-900/90 backdrop-blur-xl rounded-2xl shadow-xl shadow-gray-900/10 dark:shadow-gray-950/30 border border-gray-200/50 dark:border-gray-700/50 p-6 group hover:shadow-2xl transition-all duration-300">
              <div className="flex items-center space-x-3 mb-6">
                <div className="w-8 h-8 bg-gradient-to-br from-primary-500 to-primary-600 rounded-lg flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div>
                  <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                    Analyze Contracts
                  </h2>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Security & dependency analysis
                  </p>
                </div>
              </div>
              
              {/* Upload Form */}
              <div className="space-y-6">
                <UploadForm 
                  onAnalyze={setAnalysisData} 
                  loading={loading}
                  setLoading={setLoading}
                />
                
                {/* Divider */}
                <div className="relative py-4">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-200 dark:border-gray-700" />
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-4 bg-white dark:bg-gray-900 text-gray-500 dark:text-gray-400 font-medium">
                      OR
                    </span>
                  </div>
                </div>
                
                {/* Suiscan Input */}
                <SuiscanInput 
                  onAnalyze={setAnalysisData}
                  loading={loading}
                  setLoading={setLoading}
                />
              </div>
            </div>

            {/* Analysis Results Panel */}
            {analysisData && (
              <div className="bg-white/90 dark:bg-gray-900/90 backdrop-blur-xl rounded-2xl shadow-xl shadow-gray-900/10 dark:shadow-gray-950/30 border border-gray-200/50 dark:border-gray-700/50 p-6 animate-slide-up">
                <div className="flex items-center space-x-3 mb-6">
                  <div className="w-8 h-8 bg-gradient-to-br from-success-500 to-success-600 rounded-lg flex items-center justify-center">
                    <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-gray-900 dark:text-white">
                      Analysis Results
                    </h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Security scan complete
                    </p>
                  </div>
                </div>

                {/* Metrics Grid */}
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900/20 dark:to-blue-800/20 rounded-xl p-4 border border-blue-200/50 dark:border-blue-700/50">
                    <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                      {analysisData?.modules?.length || 0}
                    </div>
                    <div className="text-sm text-blue-600/80 dark:text-blue-400/80 font-medium">Modules</div>
                  </div>
                  <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900/20 dark:to-purple-800/20 rounded-xl p-4 border border-purple-200/50 dark:border-purple-700/50">
                    <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                      {analysisData?.functions?.length || 0}
                    </div>
                    <div className="text-sm text-purple-600/80 dark:text-purple-400/80 font-medium">Functions</div>
                  </div>
                </div>

                {/* Security Status */}
                <div className={`rounded-xl p-4 border ${
                  (analysisData?.vulnerabilities?.length || 0) > 0 
                    ? 'bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900/20 dark:to-red-800/20 border-red-200/50 dark:border-red-700/50'
                    : 'bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/20 dark:to-green-800/20 border-green-200/50 dark:border-green-700/50'
                }`}>
                  <div className="flex items-center space-x-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                      (analysisData?.vulnerabilities?.length || 0) > 0
                        ? 'bg-red-500'
                        : 'bg-green-500'
                    }`}>
                      {(analysisData?.vulnerabilities?.length || 0) > 0 ? (
                        <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.232 13.5c-.77.833.192 2.5 1.732 2.5z" />
                        </svg>
                      ) : (
                        <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      )}
                    </div>
                    <div>
                      <div className={`text-xl font-bold ${
                        (analysisData?.vulnerabilities?.length || 0) > 0
                          ? 'text-red-600 dark:text-red-400'
                          : 'text-green-600 dark:text-green-400'
                      }`}>
                        {analysisData?.vulnerabilities?.length || 0}
                      </div>
                      <div className={`text-sm font-medium ${
                        (analysisData?.vulnerabilities?.length || 0) > 0
                          ? 'text-red-600/80 dark:text-red-400/80'
                          : 'text-green-600/80 dark:text-green-400/80'
                      }`}>
                        {(analysisData?.vulnerabilities?.length || 0) > 0 ? 'Issues Found' : 'Secure'}
                      </div>
                    </div>
                  </div>
                  
                  {/* Severity Breakdown */}
                  {analysisData?.vulnerabilities?.length > 0 && (
                    <div className="mt-4 space-y-2">
                      {['high', 'medium', 'low'].map(severity => {
                        const count = analysisData.vulnerabilities.filter(v => v.severity === severity).length;
                        if (count === 0) return null;
                        const colors = {
                          high: 'bg-red-500',
                          medium: 'bg-yellow-500', 
                          low: 'bg-blue-500'
                        };
                        return (
                          <div key={severity} className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <div className={`w-2 h-2 rounded-full ${colors[severity]}`} />
                              <span className="text-xs font-medium text-gray-700 dark:text-gray-300 capitalize">
                                {severity}
                              </span>
                            </div>
                            <span className="text-xs font-bold text-gray-900 dark:text-gray-100">
                              {count}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Main Content Area */}
          <div className="lg:col-span-3 space-y-6">
            {analysisData && (
              <div className="bg-white/90 dark:bg-gray-900/90 backdrop-blur-xl rounded-2xl shadow-xl shadow-gray-900/10 dark:shadow-gray-950/30 border border-gray-200/50 dark:border-gray-700/50 overflow-hidden animate-slide-up">
                {/* Enhanced Tabs */}
                <div className="border-b border-gray-200/50 dark:border-gray-700/50 bg-gray-50/50 dark:bg-gray-800/50">
                  <nav className="flex space-x-1 p-2" aria-label="Tabs">
                    <button
                      onClick={() => setActiveTab("graph")}
                      className={`flex items-center space-x-2 px-4 py-3 rounded-xl font-medium text-sm transition-all duration-200 ${
                        activeTab === "graph"
                          ? "bg-white dark:bg-gray-800 text-primary-600 dark:text-primary-400 shadow-md ring-1 ring-primary-500/20"
                          : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:bg-white/50 dark:hover:bg-gray-800/50"
                      }`}
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                      <span>Dependency Graph</span>
                    </button>
                    <button
                      onClick={() => setActiveTab("vulnerabilities")}
                      className={`flex items-center space-x-2 px-4 py-3 rounded-xl font-medium text-sm transition-all duration-200 ${
                        activeTab === "vulnerabilities"
                          ? "bg-white dark:bg-gray-800 text-primary-600 dark:text-primary-400 shadow-md ring-1 ring-primary-500/20"
                          : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:bg-white/50 dark:hover:bg-gray-800/50"
                      }`}
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                      </svg>
                      <span>Security Report</span>
                      {analysisData?.vulnerabilities?.length > 0 && (
                        <span className="bg-red-500 text-white text-xs px-2 py-1 rounded-full font-bold animate-pulse">
                          {analysisData.vulnerabilities.length}
                        </span>
                      )}
                    </button>
                  </nav>
                </div>

                {/* Tab Content */}
                <div className="p-6">
                  {activeTab === "graph" && (
                    <div className="h-[600px] rounded-xl overflow-hidden bg-white dark:bg-gray-950 border border-gray-200 dark:border-gray-700">
                      <ErrorBoundary fallback={
                        <div className="flex items-center justify-center h-full bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900/20 dark:to-red-800/20">
                          <div className="text-center p-8">
                            <div className="w-16 h-16 bg-red-500 rounded-full flex items-center justify-center mx-auto mb-4">
                              <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.232 13.5c-.77.833.192 2.5 1.732 2.5z" />
                              </svg>
                            </div>
                            <h3 className="text-lg font-bold text-red-600 dark:text-red-400 mb-2">Graph Visualization Error</h3>
                            <p className="text-red-600/80 dark:text-red-400/80">Please try refreshing or uploading the contract again</p>
                          </div>
                        </div>
                      }>
                        <EnhancedGraphViewer data={analysisData} />
                      </ErrorBoundary>
                    </div>
                  )}
                  
                  {activeTab === "vulnerabilities" && (
                    <div className="min-h-[500px]">
                      <VulnerabilityPanel vulnerabilities={analysisData?.vulnerabilities || []} />
                    </div>
                  )}
                </div>
              </div>
            )}

            {!analysisData && (
              <div className="bg-white/90 dark:bg-gray-900/90 backdrop-blur-xl rounded-2xl shadow-xl shadow-gray-900/10 dark:shadow-gray-950/30 border border-gray-200/50 dark:border-gray-700/50 p-12 text-center animate-fade-in">
                <div className="relative">
                  {/* Floating Icons */}
                  <div className="absolute -top-6 -left-6 w-12 h-12 bg-gradient-to-br from-primary-500 to-primary-600 rounded-2xl rotate-12 flex items-center justify-center animate-bounce-slow">
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <div className="absolute -top-4 -right-4 w-8 h-8 bg-gradient-to-br from-accent-purple to-accent-pink rounded-xl -rotate-12 flex items-center justify-center animate-pulse">
                    <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                  </div>
                  
                  {/* Main Content */}
                  <div className="w-24 h-24 bg-gradient-to-br from-gray-100 to-gray-200 dark:from-gray-800 dark:to-gray-700 rounded-3xl flex items-center justify-center mx-auto mb-8 relative">
                    <svg className="w-12 h-12 text-gray-400 dark:text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                    </svg>
                    <div className="absolute -bottom-2 -right-2 w-6 h-6 bg-accent-cyan rounded-full flex items-center justify-center">
                      <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                      </svg>
                    </div>
                  </div>
                  
                  <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                    Ready to Analyze Smart Contracts
                  </h3>
                  <p className="text-gray-600 dark:text-gray-400 mb-8 max-w-md mx-auto leading-relaxed">
                    Upload Move files or enter a Suiscan URL to get started with advanced security analysis and interactive dependency visualization.
                  </p>
                  
                  {/* Feature Pills */}
                  <div className="flex flex-wrap justify-center gap-3">
                    <div className="bg-gradient-to-r from-red-500/10 to-red-600/10 dark:from-red-500/20 dark:to-red-600/20 border border-red-200 dark:border-red-700/50 text-red-700 dark:text-red-300 px-4 py-2 rounded-full text-sm font-medium">
                      🛡️ Vulnerability Detection
                    </div>
                    <div className="bg-gradient-to-r from-blue-500/10 to-blue-600/10 dark:from-blue-500/20 dark:to-blue-600/20 border border-blue-200 dark:border-blue-700/50 text-blue-700 dark:text-blue-300 px-4 py-2 rounded-full text-sm font-medium">
                      🔗 Dependency Mapping
                    </div>
                    <div className="bg-gradient-to-r from-green-500/10 to-green-600/10 dark:from-green-500/20 dark:to-green-600/20 border border-green-200 dark:border-green-700/50 text-green-700 dark:text-green-300 px-4 py-2 rounded-full text-sm font-medium">
                      📊 Security Reports
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
