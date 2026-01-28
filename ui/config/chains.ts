export interface Chain {
  id: string;
  name: string;
  symbol: string;
  addressPrefix?: string;
  bip44CoinType: number;
}

export const chains: Chain[] = [
  {
    id: "ethereum",
    name: "Ethereum",
    symbol: "ETH",
    addressPrefix: "0x",
    bip44CoinType: 60,
  },
  {
    id: "bitcoin",
    name: "Bitcoin",
    symbol: "BTC",
    bip44CoinType: 0,
  },
  {
    id: "solana",
    name: "Solana",
    symbol: "SOL",
    bip44CoinType: 501,
  },
  {
    id: "starknet",
    name: "StarkNet",
    symbol: "STRK",
    addressPrefix: "0x",
    bip44CoinType: 9004,
  },
  {
    id: "polygon",
    name: "Polygon",
    symbol: "MATIC",
    addressPrefix: "0x",
    bip44CoinType: 60,
  },
  {
    id: "arbitrum",
    name: "Arbitrum",
    symbol: "ARB",
    addressPrefix: "0x",
    bip44CoinType: 60,
  },
  {
    id: "optimism",
    name: "Optimism",
    symbol: "OP",
    addressPrefix: "0x",
    bip44CoinType: 60,
  },
  {
    id: "avalanche",
    name: "Avalanche",
    symbol: "AVAX",
    addressPrefix: "0x",
    bip44CoinType: 60,
  },
  {
    id: "base",
    name: "Base",
    symbol: "ETH",
    addressPrefix: "0x",
    bip44CoinType: 60,
  },
];

export function getChain(id: string): Chain | undefined {
  return chains.find((c) => c.id === id);
}

export function buildBip44Path(
  coinType: number,
  account: number = 0,
  change: number = 0,
  index: number = 0,
  hardened: boolean = true
): string {
  const h = hardened ? "'" : "";
  return `m/44'/${coinType}'/${account}'/${change}/${index}`;
}
