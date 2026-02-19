export const site = {
  name: "HSM",
  description: "Hardware Security Module - Cryptographic Key Management",
  url: "http://localhost:3000",
};

export const algorithms = [
  { value: "ED25519", label: "Ed25519", type: "signing" },
  { value: "ECDSA_P256", label: "ECDSA P-256", type: "signing" },
  { value: "ECDSA_P384", label: "ECDSA P-384", type: "signing" },
  { value: "RSA2048", label: "RSA 2048", type: "signing" },
  { value: "RSA3072", label: "RSA 3072", type: "signing" },
  { value: "RSA4096", label: "RSA 4096", type: "signing" },
  { value: "AES128", label: "AES-128", type: "encryption" },
  { value: "AES256", label: "AES-256", type: "encryption" },
];

export const signingAlgorithms = algorithms.filter((a) => a.type === "signing");
export const encryptionAlgorithms = algorithms.filter((a) => a.type === "encryption");

export const webhookEvents = [
  { value: "key.created", label: "Key Created" },
  { value: "key.deleted", label: "Key Deleted" },
  { value: "key.rotated", label: "Key Rotated" },
  { value: "key.deactivated", label: "Key Deactivated" },
  { value: "operation.sign", label: "Sign Operation" },
  { value: "operation.verify", label: "Verify Operation" },
  { value: "operation.encrypt", label: "Encrypt Operation" },
  { value: "operation.decrypt", label: "Decrypt Operation" },
  { value: "auth.login", label: "Login" },
  { value: "auth.logout", label: "Logout" },
  { value: "policy.evaluated", label: "Policy Evaluated" },
  { value: "backup.created", label: "Backup Created" },
  { value: "backup.restored", label: "Backup Restored" },
];
