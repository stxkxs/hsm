import { ComingSoon } from "@/components/coming-soon";

export default function BlockchainDerivePage() {
  return (
    <ComingSoon
      title="Derive Keys"
      description="BIP-32/44 key derivation"
      detail="BIP-32/44 key derivation is not yet wired to the HSM backend. This section will be enabled once the blockchain REST routes land."
    />
  );
}
