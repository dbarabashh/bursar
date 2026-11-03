import { NotImplementedError } from '../errors.ts';
import type { MppTempoPlan } from '../intent.ts';

// TODO: not ready yet: encode and sign TempoTransaction (EIP-2718 type 0x76) carrying plan.call; when plan.fee is null sign in sponsored mode (fee_token empty, fee_payer_signature 0x00), otherwise set fee_token = plan.fee.token, gas_limit and max_fee_per_gas from plan.fee; spec: https://docs.tempo.xyz/protocol/transactions/spec-tempo-transaction
export function signTempoTransaction(
  _key: Uint8Array,
  _plan: MppTempoPlan,
): never {
  throw new NotImplementedError('tempo_0x76_not_implemented');
}
