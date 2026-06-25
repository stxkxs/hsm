import { ComingSoon } from "@/components/coming-soon";

export default function PoliciesPage() {
  return (
    <ComingSoon
      title="Policies"
      description="WASM transaction policies"
      detail="WASM policy management is not yet wired to the HSM backend. The wasm-policy engine exists server-side, but uploading and managing policy modules over the REST API (multipart WASM upload + a live policy engine) is a future release."
    />
  );
}
