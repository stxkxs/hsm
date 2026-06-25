import { ComingSoon } from "@/components/coming-soon";

export default function BlockchainSignPage() {
  return (
    <ComingSoon
      title="Sign"
      description="EIP-191/712 signing"
      detail="EIP-191/712 message signing is not yet wired to the HSM backend. This section will be enabled once the blockchain REST routes land."
    />
  );
}
