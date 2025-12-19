import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'export',
  trailingSlash: true,
  // @ts-ignore
  turbopack: {
    root: '.',
  }
};

export default nextConfig;
