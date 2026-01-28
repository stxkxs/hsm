import { getAuthToken } from "./auth";
import type {
  LoginRequest,
  LoginResponse,
  MeResponse,
  Key,
  ListKeysResponse,
  CreateKeyRequest,
  CreateKeyResponse,
  SignRequest,
  SignResponse,
  VerifyRequest,
  VerifyResponse,
  EncryptRequest,
  EncryptResponse,
  DecryptRequest,
  DecryptResponse,
  Wallet,
  DeriveKeyRequest,
  DeriveKeyResponse,
  SignEip191Request,
  SignEip712Request,
  SignatureResponse,
  AddressRequest,
  AddressResponse,
  AuditParams,
  AuditResponse,
  Webhook,
  WebhookRequest,
  Policy,
  Namespace,
  HealthResponse,
  ReadyResponse,
  ApiResponse,
  ApiError,
} from "./types";

const API_BASE = "/api/hsm";

class ApiClient {
  private async fetch<T>(
    url: string,
    options?: RequestInit
  ): Promise<ApiResponse<T>> {
    const token = getAuthToken();
    const headers: HeadersInit = {
      "Content-Type": "application/json",
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options?.headers,
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (!response.ok) {
        const error: ApiError = await response.json().catch(() => ({
          code: "UNKNOWN",
          message: response.statusText,
        }));
        return { error };
      }

      // Handle 204 No Content responses
      if (response.status === 204) {
        return { data: undefined as T };
      }

      const data = await response.json();
      return { data };
    } catch (err) {
      return {
        error: {
          code: "NETWORK_ERROR",
          message: err instanceof Error ? err.message : "Network error",
        },
      };
    }
  }

  // Health
  async health(): Promise<ApiResponse<HealthResponse>> {
    return this.fetch(`${API_BASE}/health`);
  }

  async ready(): Promise<ApiResponse<ReadyResponse>> {
    return this.fetch(`${API_BASE}/ready`);
  }

  // Auth
  async login(credentials: LoginRequest): Promise<ApiResponse<LoginResponse>> {
    // Use dev-login endpoint for development
    return this.fetch(`${API_BASE}/auth/dev-login`, {
      method: "POST",
      body: JSON.stringify(credentials),
    });
  }

  async logout(): Promise<ApiResponse<void>> {
    return this.fetch(`${API_BASE}/auth/logout`, { method: "POST" });
  }

  async me(): Promise<ApiResponse<MeResponse>> {
    return this.fetch(`${API_BASE}/auth/me`);
  }

  // Keys
  async listKeys(namespace?: string): Promise<ApiResponse<ListKeysResponse>> {
    const params = namespace ? `?namespace=${encodeURIComponent(namespace)}` : "";
    return this.fetch(`${API_BASE}/keys${params}`);
  }

  async getKey(keyId: string): Promise<ApiResponse<Key>> {
    return this.fetch(`${API_BASE}/keys/${encodeURIComponent(keyId)}`);
  }

  async createKey(data: CreateKeyRequest): Promise<ApiResponse<CreateKeyResponse>> {
    return this.fetch(`${API_BASE}/keys`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async deleteKey(keyId: string): Promise<ApiResponse<void>> {
    return this.fetch(`${API_BASE}/keys/${encodeURIComponent(keyId)}`, {
      method: "DELETE",
    });
  }

  async rotateKey(keyId: string): Promise<ApiResponse<CreateKeyResponse>> {
    return this.fetch(`${API_BASE}/keys/${encodeURIComponent(keyId)}/rotate`, {
      method: "POST",
    });
  }

  // Crypto Operations
  async sign(keyId: string, data: SignRequest): Promise<ApiResponse<SignResponse>> {
    return this.fetch(`${API_BASE}/keys/${encodeURIComponent(keyId)}/sign`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async verify(keyId: string, data: VerifyRequest): Promise<ApiResponse<VerifyResponse>> {
    return this.fetch(`${API_BASE}/keys/${encodeURIComponent(keyId)}/verify`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async encrypt(keyId: string, data: EncryptRequest): Promise<ApiResponse<EncryptResponse>> {
    return this.fetch(`${API_BASE}/keys/${encodeURIComponent(keyId)}/encrypt`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async decrypt(keyId: string, data: DecryptRequest): Promise<ApiResponse<DecryptResponse>> {
    return this.fetch(`${API_BASE}/keys/${encodeURIComponent(keyId)}/decrypt`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  // Blockchain
  async listWallets(): Promise<ApiResponse<Wallet[]>> {
    return this.fetch(`${API_BASE}/blockchain/wallets`);
  }

  async createWallet(mnemonic: string, name?: string): Promise<ApiResponse<Wallet>> {
    return this.fetch(`${API_BASE}/blockchain/wallets`, {
      method: "POST",
      body: JSON.stringify({ mnemonic, name }),
    });
  }

  async deriveKey(walletId: string, data: DeriveKeyRequest): Promise<ApiResponse<DeriveKeyResponse>> {
    return this.fetch(`${API_BASE}/blockchain/wallets/${encodeURIComponent(walletId)}/derive`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async signEip191(data: SignEip191Request): Promise<ApiResponse<SignatureResponse>> {
    return this.fetch(`${API_BASE}/blockchain/sign/eip191`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async signEip712(data: SignEip712Request): Promise<ApiResponse<SignatureResponse>> {
    return this.fetch(`${API_BASE}/blockchain/sign/eip712`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async getAddresses(data: AddressRequest): Promise<ApiResponse<AddressResponse>> {
    return this.fetch(`${API_BASE}/blockchain/addresses`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  // Audit
  async getAuditLog(params?: AuditParams): Promise<ApiResponse<AuditResponse>> {
    const searchParams = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          searchParams.append(key, String(value));
        }
      });
    }
    const query = searchParams.toString();
    return this.fetch(`${API_BASE}/audit${query ? `?${query}` : ""}`);
  }

  // Webhooks
  async listWebhooks(): Promise<ApiResponse<Webhook[]>> {
    return this.fetch(`${API_BASE}/webhooks`);
  }

  async createWebhook(data: WebhookRequest): Promise<ApiResponse<Webhook>> {
    return this.fetch(`${API_BASE}/webhooks`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async getWebhook(webhookId: string): Promise<ApiResponse<Webhook>> {
    return this.fetch(`${API_BASE}/webhooks/${encodeURIComponent(webhookId)}`);
  }

  async updateWebhook(webhookId: string, data: Partial<WebhookRequest>): Promise<ApiResponse<Webhook>> {
    return this.fetch(`${API_BASE}/webhooks/${encodeURIComponent(webhookId)}`, {
      method: "PUT",
      body: JSON.stringify(data),
    });
  }

  async deleteWebhook(webhookId: string): Promise<ApiResponse<void>> {
    return this.fetch(`${API_BASE}/webhooks/${encodeURIComponent(webhookId)}`, {
      method: "DELETE",
    });
  }

  async testWebhook(webhookId: string): Promise<ApiResponse<{ success: boolean }>> {
    return this.fetch(`${API_BASE}/webhooks/${encodeURIComponent(webhookId)}/test`, {
      method: "POST",
    });
  }

  // Policies
  async listPolicies(): Promise<ApiResponse<Policy[]>> {
    return this.fetch(`${API_BASE}/policies`);
  }

  async createPolicy(data: FormData): Promise<ApiResponse<Policy>> {
    const token = getAuthToken();
    const response = await fetch(`${API_BASE}/policies`, {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: data,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({
        code: "UNKNOWN",
        message: response.statusText,
      }));
      return { error };
    }

    return { data: await response.json() };
  }

  async getPolicy(policyId: string): Promise<ApiResponse<Policy>> {
    return this.fetch(`${API_BASE}/policies/${encodeURIComponent(policyId)}`);
  }

  async deletePolicy(policyId: string): Promise<ApiResponse<void>> {
    return this.fetch(`${API_BASE}/policies/${encodeURIComponent(policyId)}`, {
      method: "DELETE",
    });
  }

  async attachPolicy(policyId: string, namespace: string): Promise<ApiResponse<void>> {
    return this.fetch(`${API_BASE}/policies/${encodeURIComponent(policyId)}/attach`, {
      method: "POST",
      body: JSON.stringify({ namespace }),
    });
  }

  // Namespaces
  async listNamespaces(): Promise<ApiResponse<Namespace[]>> {
    return this.fetch(`${API_BASE}/namespaces`);
  }

  async createNamespace(name: string): Promise<ApiResponse<Namespace>> {
    return this.fetch(`${API_BASE}/namespaces`, {
      method: "POST",
      body: JSON.stringify({ name }),
    });
  }

  async getNamespace(name: string): Promise<ApiResponse<Namespace>> {
    return this.fetch(`${API_BASE}/namespaces/${encodeURIComponent(name)}`);
  }

  async deleteNamespace(name: string): Promise<ApiResponse<void>> {
    return this.fetch(`${API_BASE}/namespaces/${encodeURIComponent(name)}`, {
      method: "DELETE",
    });
  }
}

export const hsmApi = new ApiClient();
