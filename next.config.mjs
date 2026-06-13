/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    // The scanner libraries are server-only; keep them out of the client bundle.
    serverComponentsExternalPackages: [
      "bullmq",
      "ioredis",
      "@anthropic-ai/sdk",
      "node-html-parser",
    ],
  },
};

export default nextConfig;
