package api

// Compatibility names for models used by the high-level client. Ogen now names
// single-reference allOf schemas after the endpoint or containing property.
// Keep these aliases outside generated files so regeneration preserves them.
type TokenInfo = AuthenticationTokensResponseAccessToken
type FormCode = SessionsOnlinePostReqFormCode
type EncryptionInfo = SessionsOnlinePostReqEncryption
type BatchFileInfo = SessionsBatchPostReqBatchFile
type InvoicePackage = InvoiceExportStatusResponsePackage
type OptNilInvoicePackage = OptNilInvoiceExportStatusResponsePackage
type InvoiceQueryFilters = InvoicesQueryMetadataPostReq
type OptInvoiceQueryFilters = OptInvoicesQueryMetadataPostReq
type InvoiceQueryDateRange = InvoicesQueryMetadataPostReqDateRange
type InvoiceQueryAmount = InvoicesQueryMetadataPostReqAmount
type InvoiceQueryBuyerIdentifier = InvoicesQueryMetadataPostReqBuyerIdentifier
type InitTokenAuthenticationRequest = AuthKsefTokenPostReq
type AuthenticationContextIdentifier = AuthKsefTokenPostReqContextIdentifier
type OpenOnlineSessionRequest = SessionsOnlinePostReq
type OptOpenOnlineSessionRequest = OptSessionsOnlinePostReq
type OpenBatchSessionRequest = SessionsBatchPostReq
type OptOpenBatchSessionRequest = OptSessionsBatchPostReq
type SendInvoiceRequest = SessionsOnlineReferenceNumberInvoicesPostReq
type OptSendInvoiceRequest = OptSessionsOnlineReferenceNumberInvoicesPostReq
type InvoiceExportRequest = InvoicesExportsPostReq
type OptInvoiceExportRequest = OptInvoicesExportsPostReq

func NewOptInitTokenAuthenticationRequest(v InitTokenAuthenticationRequest) OptAuthKsefTokenPostReq {
	return NewOptAuthKsefTokenPostReq(v)
}

func NewOptNilInvoicePackage(v InvoicePackage) OptNilInvoicePackage {
	return NewOptNilInvoiceExportStatusResponsePackage(v)
}
