"use client";

import { useState } from "react";
import { fetchContract } from "@/utils/api";

interface SuiscanInputProps {
  onAnalyze: (data: any) => void;
  loading: boolean;
  setLoading: (loading: boolean) => void;
}

export default function SuiscanInput({ onAnalyze, loading, setLoading }: SuiscanInputProps) {
  const [input, setInput] = useState("");
  const [inputType, setInputType] = useState<"url" | "object" | "package">("url");

  const detectInputType = (value: string) => {
    if (value.includes("suiscan.xyz") || value.includes("suivision.xyz")) {
      setInputType("url");
    } else if (value.startsWith("0x") && value.length === 66) {
      setInputType("object");
    } else if (value.startsWith("0x") && value.length === 64) {
      setInputType("package");
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setInput(value);
    if (value) {
      detectInputType(value);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    setLoading(true);
    try {
      const result = await fetchContract(input.trim(), inputType);
      onAnalyze(result);
    } catch (error) {
      console.error('Fetch failed:', error);
      alert('Failed to fetch contract. Please check the URL/ID and try again.');
    } finally {
      setLoading(false);
    }
  };

  const getPlaceholder = () => {
    switch (inputType) {
      case "url":
        return "https://suiscan.xyz/mainnet/object/0x...";
      case "object":
        return "0x... (Object ID)";
      case "package":
        return "0x... (Package Address)";
      default:
        return "Suiscan URL, Object ID, or Package Address";
    }
  };

  const getInputTypeDisplay = () => {
    switch (inputType) {
      case "url":
        return "Suiscan URL";
      case "object":
        return "Object ID";
      case "package":
        return "Package Address";
      default:
        return "Auto-detect";
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="suiscan-input" className="block text-sm font-medium text-gray-700 mb-2">
          Scan Deployed Contract
        </label>
        <div className="relative">
          <input
            id="suiscan-input"
            type="text"
            value={input}
            onChange={handleInputChange}
            placeholder={getPlaceholder()}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
          {input && (
            <div className="absolute right-3 top-2 text-xs text-gray-500 bg-white px-1">
              {getInputTypeDisplay()}
            </div>
          )}
        </div>
        <p className="mt-1 text-xs text-gray-500">
          Paste a Suiscan URL, Object ID, or Package Address to analyze deployed contracts
        </p>
      </div>

      {/* Examples */}
      <div className="bg-gray-50 p-3 rounded-md">
        <h5 className="text-xs font-medium text-gray-700 mb-2">Examples:</h5>
        <div className="space-y-1 text-xs text-gray-600">
          <div>• Suiscan URL: https://suiscan.xyz/mainnet/object/0x...</div>
          <div>• Object ID: 0x1234...abcd (66 chars)</div>
          <div>• Package: 0x1234...abcd (64 chars)</div>
        </div>
      </div>

      <button
        type="submit"
        disabled={!input.trim() || loading}
        className={`w-full py-2 px-4 rounded-md text-white font-medium transition-colors ${
          !input.trim() || loading
            ? 'bg-gray-400 cursor-not-allowed'
            : 'bg-green-600 hover:bg-green-700'
        }`}
      >
        {loading ? 'Fetching...' : 'Scan Contract'}
      </button>
    </form>
  );
}