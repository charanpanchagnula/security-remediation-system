import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // 'output: export' disables rewrites — removed so API proxy works in dev.
  trailingSlash: true,
  async rewrites() {
    return [
      {
        source: '/api/v1/:path*',
        destination: 'http://localhost:8000/api/v1/:path*',
      },
    ];
  },
};

export default nextConfig;
