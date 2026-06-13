import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelScan — Web Güvenlik Denetleyici",
  description:
    "Claude Opus 4.8 dinamik iş akışlarıyla çalışan, kurumsal SaaS web uygulaması güvenlik tarayıcısı.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="tr">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
