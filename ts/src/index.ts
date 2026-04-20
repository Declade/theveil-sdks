export { TheVeil } from './client.js';
export {
  TheVeilError,
  TheVeilConfigError,
  TheVeilHttpError,
  TheVeilTimeoutError,
  TheVeilCertificateError,
} from './errors.js';
export type { VerifyCertificateFailureReason } from './errors.js';
export type {
  TheVeilConfig,
  ProxyRequest,
  ProxyResponse,
  ProxySyncResponse,
  ProxyAcceptedResponse,
  ProxyJobStatus,
  ProxyVeilReceipt,
  ProxyPIIAnnotation,
  ProxyMessagesRequest,
  MessagesOptions,
  VeilCertificate,
  VeilClaim,
  VeilVerificationResult,
  VeilAnchorStatusInfo,
  VeilExternalAttestation,
  VeilCertAnchorStatus,
  VeilVerdict,
  VeilCompleteness,
  VeilClaimType,
  VeilIsolationProbeStatus,
  VerifyCertificateKeys,
  VerifyCertificateResult,
} from './types.js';
