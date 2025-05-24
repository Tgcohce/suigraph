import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/contexts/ThemeContext";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "SuiGraph - Smart Contract Security Analyzer",
  description: "Advanced security analysis and visualization tool for Sui blockchain smart contracts. Analyze Move code, detect vulnerabilities, and visualize dependencies.",
  keywords: ["sui", "blockchain", "smart contracts", "security", "analysis", "move language", "vulnerability scanner"],
  authors: [{ name: "SuiGraph Team" }],
  openGraph: {
    title: "SuiGraph - Smart Contract Security Analyzer",
    description: "Advanced security analysis and visualization tool for Sui blockchain smart contracts",
    type: "website",
  },
  viewport: "width=device-width, initial-scale=1",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/favicon.ico" />
        <meta name="theme-color" content="#0f172a" />
      </head>
      <body
        className={`${inter.variable} ${jetbrainsMono.variable} antialiased font-sans`}
      >
        <ThemeProvider>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
