/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/api/hsm/:path*',
        destination: `${process.env.HSM_API_URL || 'http://localhost:8443'}/:path*`,
      },
    ];
  },
};

export default nextConfig;
