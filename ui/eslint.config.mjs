// Flat ESLint config (ESLint 10 / Next 16). Next 16 removed the `next lint`
// subcommand, so linting now runs ESLint directly against this flat config.
import next from "eslint-config-next";

const nextConfigs = Array.isArray(next) ? next : [next];

const config = [
  ...nextConfigs,
  {
    ignores: [".next/**", "out/**", "node_modules/**", "cypress/**"],
  },
  {
    rules: {
      // eslint-config-next 16 adds this advisory (synchronous setState in an
      // effect can cascade renders). The data-fetch hooks/pages use the standard
      // setLoading(true)→await→setData pattern, which is functional, not a bug.
      // Keep it visible as a warning rather than blocking; a focused refactor can
      // address it later.
      "react-hooks/set-state-in-effect": "warn",
    },
  },
];

export default config;
