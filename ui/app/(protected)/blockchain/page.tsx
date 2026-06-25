import { ComingSoon } from "@/components/coming-soon";

export default function BlockchainPage() {
  return (
    <ComingSoon
      title="Blockchain"
      description="HD wallets and Web3 signing"
      detail="HD wallet management and multi-chain signing are not yet wired to the HSM backend. The blockchain crate implements BIP-32/39/44 and EIP-191/712, and its experimental chain signers (Aptos/Sui/NEAR) are gated behind a feature flag; this UI section will be enabled once the backend routes land."
    />
  );
}
