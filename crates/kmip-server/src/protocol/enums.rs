//! KMIP Enumerations
//!
//! These enumerations are defined by the KMIP specification and are used
//! throughout the protocol for identifying operations, object types,
//! algorithms, and result statuses.

/// KMIP Operation
///
/// Identifies the type of operation being requested or responded to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Operation {
    Create = 0x00000001,
    CreateKeyPair = 0x00000002,
    Register = 0x00000003,
    ReKey = 0x00000004,
    DeriveKey = 0x00000005,
    Certify = 0x00000006,
    ReCertify = 0x00000007,
    Locate = 0x00000008,
    Check = 0x00000009,
    Get = 0x0000000A,
    GetAttributes = 0x0000000B,
    GetAttributeList = 0x0000000C,
    AddAttribute = 0x0000000D,
    ModifyAttribute = 0x0000000E,
    DeleteAttribute = 0x0000000F,
    ObtainLease = 0x00000010,
    GetUsageAllocation = 0x00000011,
    Activate = 0x00000012,
    Revoke = 0x00000013,
    Destroy = 0x00000014,
    Archive = 0x00000015,
    Recover = 0x00000016,
    Validate = 0x00000017,
    Query = 0x00000018,
    Cancel = 0x00000019,
    Poll = 0x0000001A,
    Notify = 0x0000001B,
    Put = 0x0000001C,
    // 0x1D and 0x1E reserved
    Encrypt = 0x0000001F,
    Decrypt = 0x00000020,
    Sign = 0x00000021,
    SignatureVerify = 0x00000022,
    Mac = 0x00000023,
    MacVerify = 0x00000024,
    RngRetrieve = 0x00000025,
    RngSeed = 0x00000026,
    Hash = 0x00000027,
    CreateSplitKey = 0x00000028,
    JoinSplitKey = 0x00000029,
}

impl TryFrom<u32> for Operation {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(Operation::Create),
            0x02 => Ok(Operation::CreateKeyPair),
            0x03 => Ok(Operation::Register),
            0x04 => Ok(Operation::ReKey),
            0x05 => Ok(Operation::DeriveKey),
            0x06 => Ok(Operation::Certify),
            0x07 => Ok(Operation::ReCertify),
            0x08 => Ok(Operation::Locate),
            0x09 => Ok(Operation::Check),
            0x0A => Ok(Operation::Get),
            0x0B => Ok(Operation::GetAttributes),
            0x0C => Ok(Operation::GetAttributeList),
            0x0D => Ok(Operation::AddAttribute),
            0x0E => Ok(Operation::ModifyAttribute),
            0x0F => Ok(Operation::DeleteAttribute),
            0x10 => Ok(Operation::ObtainLease),
            0x11 => Ok(Operation::GetUsageAllocation),
            0x12 => Ok(Operation::Activate),
            0x13 => Ok(Operation::Revoke),
            0x14 => Ok(Operation::Destroy),
            0x15 => Ok(Operation::Archive),
            0x16 => Ok(Operation::Recover),
            0x17 => Ok(Operation::Validate),
            0x18 => Ok(Operation::Query),
            0x19 => Ok(Operation::Cancel),
            0x1A => Ok(Operation::Poll),
            0x1B => Ok(Operation::Notify),
            0x1C => Ok(Operation::Put),
            0x1F => Ok(Operation::Encrypt),
            0x20 => Ok(Operation::Decrypt),
            0x21 => Ok(Operation::Sign),
            0x22 => Ok(Operation::SignatureVerify),
            0x23 => Ok(Operation::Mac),
            0x24 => Ok(Operation::MacVerify),
            0x25 => Ok(Operation::RngRetrieve),
            0x26 => Ok(Operation::RngSeed),
            0x27 => Ok(Operation::Hash),
            0x28 => Ok(Operation::CreateSplitKey),
            0x29 => Ok(Operation::JoinSplitKey),
            _ => Err(()),
        }
    }
}

impl From<Operation> for u32 {
    fn from(op: Operation) -> Self {
        op as u32
    }
}

/// Object Type
///
/// Identifies the type of managed object (key, certificate, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ObjectType {
    Certificate = 0x00000001,
    SymmetricKey = 0x00000002,
    PublicKey = 0x00000003,
    PrivateKey = 0x00000004,
    SplitKey = 0x00000005,
    Template = 0x00000006,
    SecretData = 0x00000007,
    OpaqueObject = 0x00000008,
    PgpKey = 0x00000009,
}

impl TryFrom<u32> for ObjectType {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(ObjectType::Certificate),
            0x02 => Ok(ObjectType::SymmetricKey),
            0x03 => Ok(ObjectType::PublicKey),
            0x04 => Ok(ObjectType::PrivateKey),
            0x05 => Ok(ObjectType::SplitKey),
            0x06 => Ok(ObjectType::Template),
            0x07 => Ok(ObjectType::SecretData),
            0x08 => Ok(ObjectType::OpaqueObject),
            0x09 => Ok(ObjectType::PgpKey),
            _ => Err(()),
        }
    }
}

impl From<ObjectType> for u32 {
    fn from(t: ObjectType) -> Self {
        t as u32
    }
}

/// Cryptographic Algorithm
///
/// Identifies the cryptographic algorithm used with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CryptographicAlgorithm {
    Des = 0x00000001,
    TripleDes = 0x00000002,
    Aes = 0x00000003,
    Rsa = 0x00000004,
    Dsa = 0x00000005,
    Ecdsa = 0x00000006,
    HmacSha1 = 0x00000007,
    HmacSha224 = 0x00000008,
    HmacSha256 = 0x00000009,
    HmacSha384 = 0x0000000A,
    HmacSha512 = 0x0000000B,
    HmacMd5 = 0x0000000C,
    Dh = 0x0000000D,
    Ecdh = 0x0000000E,
    Ecmqv = 0x0000000F,
    Blowfish = 0x00000010,
    Camellia = 0x00000011,
    Cast5 = 0x00000012,
    Idea = 0x00000013,
    Mars = 0x00000014,
    Rc2 = 0x00000015,
    Rc4 = 0x00000016,
    Rc5 = 0x00000017,
    Skipjack = 0x00000018,
    Twofish = 0x00000019,
    Ec = 0x0000001A,
    // Extensions
    Ed25519 = 0x0000001B,
    Ed448 = 0x0000001C,
    ChaCha20 = 0x0000001D,
    ChaCha20Poly1305 = 0x0000001E,
}

impl TryFrom<u32> for CryptographicAlgorithm {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(CryptographicAlgorithm::Des),
            0x02 => Ok(CryptographicAlgorithm::TripleDes),
            0x03 => Ok(CryptographicAlgorithm::Aes),
            0x04 => Ok(CryptographicAlgorithm::Rsa),
            0x05 => Ok(CryptographicAlgorithm::Dsa),
            0x06 => Ok(CryptographicAlgorithm::Ecdsa),
            0x07 => Ok(CryptographicAlgorithm::HmacSha1),
            0x08 => Ok(CryptographicAlgorithm::HmacSha224),
            0x09 => Ok(CryptographicAlgorithm::HmacSha256),
            0x0A => Ok(CryptographicAlgorithm::HmacSha384),
            0x0B => Ok(CryptographicAlgorithm::HmacSha512),
            0x0C => Ok(CryptographicAlgorithm::HmacMd5),
            0x0D => Ok(CryptographicAlgorithm::Dh),
            0x0E => Ok(CryptographicAlgorithm::Ecdh),
            0x0F => Ok(CryptographicAlgorithm::Ecmqv),
            0x10 => Ok(CryptographicAlgorithm::Blowfish),
            0x11 => Ok(CryptographicAlgorithm::Camellia),
            0x12 => Ok(CryptographicAlgorithm::Cast5),
            0x13 => Ok(CryptographicAlgorithm::Idea),
            0x14 => Ok(CryptographicAlgorithm::Mars),
            0x15 => Ok(CryptographicAlgorithm::Rc2),
            0x16 => Ok(CryptographicAlgorithm::Rc4),
            0x17 => Ok(CryptographicAlgorithm::Rc5),
            0x18 => Ok(CryptographicAlgorithm::Skipjack),
            0x19 => Ok(CryptographicAlgorithm::Twofish),
            0x1A => Ok(CryptographicAlgorithm::Ec),
            0x1B => Ok(CryptographicAlgorithm::Ed25519),
            0x1C => Ok(CryptographicAlgorithm::Ed448),
            0x1D => Ok(CryptographicAlgorithm::ChaCha20),
            0x1E => Ok(CryptographicAlgorithm::ChaCha20Poly1305),
            _ => Err(()),
        }
    }
}

impl From<CryptographicAlgorithm> for u32 {
    fn from(alg: CryptographicAlgorithm) -> Self {
        alg as u32
    }
}

/// Block Cipher Mode
///
/// Identifies the mode of operation for block ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum BlockCipherMode {
    Cbc = 0x00000001,
    Ecb = 0x00000002,
    Pcbc = 0x00000003,
    Cfb = 0x00000004,
    Ofb = 0x00000005,
    Ctr = 0x00000006,
    Cmac = 0x00000007,
    Ccm = 0x00000008,
    Gcm = 0x00000009,
    CbcMac = 0x0000000A,
    Xts = 0x0000000B,
    AesKeyWrapPadding = 0x0000000C,
    NistKeyWrap = 0x0000000D,
    X9102Aead = 0x0000000E,
    X9102Aes = 0x0000000F,
    X9102Tdea = 0x00000010,
}

impl TryFrom<u32> for BlockCipherMode {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(BlockCipherMode::Cbc),
            0x02 => Ok(BlockCipherMode::Ecb),
            0x03 => Ok(BlockCipherMode::Pcbc),
            0x04 => Ok(BlockCipherMode::Cfb),
            0x05 => Ok(BlockCipherMode::Ofb),
            0x06 => Ok(BlockCipherMode::Ctr),
            0x07 => Ok(BlockCipherMode::Cmac),
            0x08 => Ok(BlockCipherMode::Ccm),
            0x09 => Ok(BlockCipherMode::Gcm),
            0x0A => Ok(BlockCipherMode::CbcMac),
            0x0B => Ok(BlockCipherMode::Xts),
            0x0C => Ok(BlockCipherMode::AesKeyWrapPadding),
            0x0D => Ok(BlockCipherMode::NistKeyWrap),
            0x0E => Ok(BlockCipherMode::X9102Aead),
            0x0F => Ok(BlockCipherMode::X9102Aes),
            0x10 => Ok(BlockCipherMode::X9102Tdea),
            _ => Err(()),
        }
    }
}

impl From<BlockCipherMode> for u32 {
    fn from(mode: BlockCipherMode) -> Self {
        mode as u32
    }
}

/// Padding Method
///
/// Identifies the padding method used for block ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum PaddingMethod {
    None = 0x00000001,
    Oaep = 0x00000002,
    Pkcs5 = 0x00000003,
    Ssl3 = 0x00000004,
    Zeros = 0x00000005,
    AnsiX923 = 0x00000006,
    Iso10126 = 0x00000007,
    Pkcs1V15 = 0x00000008,
    X931 = 0x00000009,
    Pss = 0x0000000A,
}

impl TryFrom<u32> for PaddingMethod {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(PaddingMethod::None),
            0x02 => Ok(PaddingMethod::Oaep),
            0x03 => Ok(PaddingMethod::Pkcs5),
            0x04 => Ok(PaddingMethod::Ssl3),
            0x05 => Ok(PaddingMethod::Zeros),
            0x06 => Ok(PaddingMethod::AnsiX923),
            0x07 => Ok(PaddingMethod::Iso10126),
            0x08 => Ok(PaddingMethod::Pkcs1V15),
            0x09 => Ok(PaddingMethod::X931),
            0x0A => Ok(PaddingMethod::Pss),
            _ => Err(()),
        }
    }
}

impl From<PaddingMethod> for u32 {
    fn from(method: PaddingMethod) -> Self {
        method as u32
    }
}

/// Hashing Algorithm
///
/// Identifies the hashing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum HashingAlgorithm {
    Md2 = 0x00000001,
    Md4 = 0x00000002,
    Md5 = 0x00000003,
    Sha1 = 0x00000004,
    Sha224 = 0x00000005,
    Sha256 = 0x00000006,
    Sha384 = 0x00000007,
    Sha512 = 0x00000008,
    Ripemd160 = 0x00000009,
    Tiger = 0x0000000A,
    Whirlpool = 0x0000000B,
    Sha512224 = 0x0000000C,
    Sha512256 = 0x0000000D,
    Sha3224 = 0x0000000E,
    Sha3256 = 0x0000000F,
    Sha3384 = 0x00000010,
    Sha3512 = 0x00000011,
}

impl TryFrom<u32> for HashingAlgorithm {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(HashingAlgorithm::Md2),
            0x02 => Ok(HashingAlgorithm::Md4),
            0x03 => Ok(HashingAlgorithm::Md5),
            0x04 => Ok(HashingAlgorithm::Sha1),
            0x05 => Ok(HashingAlgorithm::Sha224),
            0x06 => Ok(HashingAlgorithm::Sha256),
            0x07 => Ok(HashingAlgorithm::Sha384),
            0x08 => Ok(HashingAlgorithm::Sha512),
            0x09 => Ok(HashingAlgorithm::Ripemd160),
            0x0A => Ok(HashingAlgorithm::Tiger),
            0x0B => Ok(HashingAlgorithm::Whirlpool),
            0x0C => Ok(HashingAlgorithm::Sha512224),
            0x0D => Ok(HashingAlgorithm::Sha512256),
            0x0E => Ok(HashingAlgorithm::Sha3224),
            0x0F => Ok(HashingAlgorithm::Sha3256),
            0x10 => Ok(HashingAlgorithm::Sha3384),
            0x11 => Ok(HashingAlgorithm::Sha3512),
            _ => Err(()),
        }
    }
}

impl From<HashingAlgorithm> for u32 {
    fn from(alg: HashingAlgorithm) -> Self {
        alg as u32
    }
}

/// Key Format Type
///
/// Identifies the format of key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum KeyFormatType {
    Raw = 0x00000001,
    Opaque = 0x00000002,
    Pkcs1 = 0x00000003,
    Pkcs8 = 0x00000004,
    X509 = 0x00000005,
    EcPrivateKey = 0x00000006,
    TransparentSymmetricKey = 0x00000007,
    TransparentDsaPrivateKey = 0x00000008,
    TransparentDsaPublicKey = 0x00000009,
    TransparentRsaPrivateKey = 0x0000000A,
    TransparentRsaPublicKey = 0x0000000B,
    TransparentDhPrivateKey = 0x0000000C,
    TransparentDhPublicKey = 0x0000000D,
    TransparentEcPrivateKey = 0x00000014,
    TransparentEcPublicKey = 0x00000015,
    Pkcs12 = 0x00000016,
}

impl TryFrom<u32> for KeyFormatType {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(KeyFormatType::Raw),
            0x02 => Ok(KeyFormatType::Opaque),
            0x03 => Ok(KeyFormatType::Pkcs1),
            0x04 => Ok(KeyFormatType::Pkcs8),
            0x05 => Ok(KeyFormatType::X509),
            0x06 => Ok(KeyFormatType::EcPrivateKey),
            0x07 => Ok(KeyFormatType::TransparentSymmetricKey),
            0x08 => Ok(KeyFormatType::TransparentDsaPrivateKey),
            0x09 => Ok(KeyFormatType::TransparentDsaPublicKey),
            0x0A => Ok(KeyFormatType::TransparentRsaPrivateKey),
            0x0B => Ok(KeyFormatType::TransparentRsaPublicKey),
            0x0C => Ok(KeyFormatType::TransparentDhPrivateKey),
            0x0D => Ok(KeyFormatType::TransparentDhPublicKey),
            0x14 => Ok(KeyFormatType::TransparentEcPrivateKey),
            0x15 => Ok(KeyFormatType::TransparentEcPublicKey),
            0x16 => Ok(KeyFormatType::Pkcs12),
            _ => Err(()),
        }
    }
}

impl From<KeyFormatType> for u32 {
    fn from(fmt: KeyFormatType) -> Self {
        fmt as u32
    }
}

/// Result Status
///
/// Indicates the success or failure of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ResultStatus {
    Success = 0x00000000,
    OperationFailed = 0x00000001,
    OperationPending = 0x00000002,
    OperationUndone = 0x00000003,
}

impl TryFrom<u32> for ResultStatus {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x00 => Ok(ResultStatus::Success),
            0x01 => Ok(ResultStatus::OperationFailed),
            0x02 => Ok(ResultStatus::OperationPending),
            0x03 => Ok(ResultStatus::OperationUndone),
            _ => Err(()),
        }
    }
}

impl From<ResultStatus> for u32 {
    fn from(status: ResultStatus) -> Self {
        status as u32
    }
}

/// Result Reason
///
/// Provides details about why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ResultReason {
    ItemNotFound = 0x00000001,
    ResponseTooLarge = 0x00000002,
    AuthenticationNotSuccessful = 0x00000003,
    InvalidMessage = 0x00000004,
    OperationNotSupported = 0x00000005,
    MissingData = 0x00000006,
    InvalidField = 0x00000007,
    FeatureNotSupported = 0x00000008,
    OperationCanceledByRequester = 0x00000009,
    CryptographicFailure = 0x0000000A,
    IllegalOperation = 0x0000000B,
    PermissionDenied = 0x0000000C,
    ObjectArchived = 0x0000000D,
    IndexOutOfBounds = 0x0000000E,
    ApplicationNamespaceNotSupported = 0x0000000F,
    KeyFormatNotSupported = 0x00000010,
    KeyCompressionTypeNotSupported = 0x00000011,
    EncodingOptionError = 0x00000012,
    KeyValueNotPresent = 0x00000013,
    AttestationRequired = 0x00000014,
    AttestationFailed = 0x00000015,
    Sensitive = 0x00000016,
    NotExtractable = 0x00000017,
    ObjectAlreadyExists = 0x00000018,
    InvalidTicket = 0x00000019,
    UsageLimitExceeded = 0x0000001A,
    NumericRange = 0x0000001B,
    InvalidDataType = 0x0000001C,
    ReadOnlyAttribute = 0x0000001D,
    MultiValuedAttribute = 0x0000001E,
    UnsupportedAttribute = 0x0000001F,
    AttributeInstanceNotFound = 0x00000020,
    AttributeNotFound = 0x00000021,
    AttributeReadOnly = 0x00000022,
    AttributeSingleValued = 0x00000023,
    BadCryptographicParameters = 0x00000024,
    BadPassword = 0x00000025,
    CodecError = 0x00000026,
    IllegalObjectType = 0x00000028,
    IncompatibleCryptographicUsageMask = 0x00000029,
    InternalServerError = 0x0000002A,
    InvalidAsynchronousCorrelationValue = 0x0000002B,
    InvalidAttribute = 0x0000002C,
    InvalidAttributeValue = 0x0000002D,
    InvalidCorrelationValue = 0x0000002E,
    InvalidCsr = 0x0000002F,
    InvalidObjectType = 0x00000030,
    KeyWrapTypeNotSupported = 0x00000032,
    MissingInitializationVector = 0x00000034,
    NonUniqueNameAttribute = 0x00000035,
    ObjectDestroyed = 0x00000036,
    ObjectNotFound = 0x00000037,
    NotAuthorized = 0x00000039,
    ServerLimitExceeded = 0x0000003A,
    UnknownEnumeration = 0x0000003B,
    UnknownMessageExtension = 0x0000003C,
    UnknownTag = 0x0000003D,
    UnsupportedCryptographicParameters = 0x0000003E,
    UnsupportedProtocolVersion = 0x0000003F,
    WrappingObjectArchived = 0x00000040,
    WrappingObjectDestroyed = 0x00000041,
    WrappingObjectNotFound = 0x00000042,
    WrongKeyLifecycleState = 0x00000043,
    ProtectionStorageUnavailable = 0x00000044,
    Pkcs11CodecError = 0x00000045,
    Pkcs11InvalidFunction = 0x00000046,
    Pkcs11InvalidInterface = 0x00000047,
    PrivateProtectionStorageUnavailable = 0x00000048,
    PublicProtectionStorageUnavailable = 0x00000049,
    GeneralFailure = 0x00000100,
}

impl TryFrom<u32> for ResultReason {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(ResultReason::ItemNotFound),
            0x02 => Ok(ResultReason::ResponseTooLarge),
            0x03 => Ok(ResultReason::AuthenticationNotSuccessful),
            0x04 => Ok(ResultReason::InvalidMessage),
            0x05 => Ok(ResultReason::OperationNotSupported),
            0x06 => Ok(ResultReason::MissingData),
            0x07 => Ok(ResultReason::InvalidField),
            0x08 => Ok(ResultReason::FeatureNotSupported),
            0x09 => Ok(ResultReason::OperationCanceledByRequester),
            0x0A => Ok(ResultReason::CryptographicFailure),
            0x0B => Ok(ResultReason::IllegalOperation),
            0x0C => Ok(ResultReason::PermissionDenied),
            0x0D => Ok(ResultReason::ObjectArchived),
            0x0E => Ok(ResultReason::IndexOutOfBounds),
            0x0F => Ok(ResultReason::ApplicationNamespaceNotSupported),
            0x10 => Ok(ResultReason::KeyFormatNotSupported),
            0x11 => Ok(ResultReason::KeyCompressionTypeNotSupported),
            0x12 => Ok(ResultReason::EncodingOptionError),
            0x13 => Ok(ResultReason::KeyValueNotPresent),
            0x14 => Ok(ResultReason::AttestationRequired),
            0x15 => Ok(ResultReason::AttestationFailed),
            0x16 => Ok(ResultReason::Sensitive),
            0x17 => Ok(ResultReason::NotExtractable),
            0x18 => Ok(ResultReason::ObjectAlreadyExists),
            0x100 => Ok(ResultReason::GeneralFailure),
            _ => Err(()),
        }
    }
}

impl From<ResultReason> for u32 {
    fn from(reason: ResultReason) -> Self {
        reason as u32
    }
}

/// Key State (lifecycle)
///
/// Indicates the current state of a key in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum KeyState {
    PreActive = 0x00000001,
    Active = 0x00000002,
    Deactivated = 0x00000003,
    Compromised = 0x00000004,
    Destroyed = 0x00000005,
    DestroyedCompromised = 0x00000006,
}

impl TryFrom<u32> for KeyState {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(KeyState::PreActive),
            0x02 => Ok(KeyState::Active),
            0x03 => Ok(KeyState::Deactivated),
            0x04 => Ok(KeyState::Compromised),
            0x05 => Ok(KeyState::Destroyed),
            0x06 => Ok(KeyState::DestroyedCompromised),
            _ => Err(()),
        }
    }
}

impl From<KeyState> for u32 {
    fn from(state: KeyState) -> Self {
        state as u32
    }
}

/// Revocation Reason Code
///
/// Indicates why a key was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum RevocationReasonCode {
    Unspecified = 0x00000001,
    KeyCompromise = 0x00000002,
    CaCompromise = 0x00000003,
    AffiliationChanged = 0x00000004,
    Superseded = 0x00000005,
    CessationOfOperation = 0x00000006,
    PrivilegeWithdrawn = 0x00000007,
}

impl TryFrom<u32> for RevocationReasonCode {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(RevocationReasonCode::Unspecified),
            0x02 => Ok(RevocationReasonCode::KeyCompromise),
            0x03 => Ok(RevocationReasonCode::CaCompromise),
            0x04 => Ok(RevocationReasonCode::AffiliationChanged),
            0x05 => Ok(RevocationReasonCode::Superseded),
            0x06 => Ok(RevocationReasonCode::CessationOfOperation),
            0x07 => Ok(RevocationReasonCode::PrivilegeWithdrawn),
            _ => Err(()),
        }
    }
}

impl From<RevocationReasonCode> for u32 {
    fn from(code: RevocationReasonCode) -> Self {
        code as u32
    }
}

/// Query Function
///
/// Identifies what information to query from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum QueryFunction {
    QueryOperations = 0x00000001,
    QueryObjects = 0x00000002,
    QueryServerInformation = 0x00000003,
    QueryApplicationNamespaces = 0x00000004,
    QueryExtensionList = 0x00000005,
    QueryExtensionMap = 0x00000006,
    QueryAttestationTypes = 0x00000007,
    QueryRngs = 0x00000008,
    QueryValidations = 0x00000009,
    QueryProfiles = 0x0000000A,
    QueryCapabilities = 0x0000000B,
    QueryClientRegistrationMethods = 0x0000000C,
}

impl TryFrom<u32> for QueryFunction {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(QueryFunction::QueryOperations),
            0x02 => Ok(QueryFunction::QueryObjects),
            0x03 => Ok(QueryFunction::QueryServerInformation),
            0x04 => Ok(QueryFunction::QueryApplicationNamespaces),
            0x05 => Ok(QueryFunction::QueryExtensionList),
            0x06 => Ok(QueryFunction::QueryExtensionMap),
            0x07 => Ok(QueryFunction::QueryAttestationTypes),
            0x08 => Ok(QueryFunction::QueryRngs),
            0x09 => Ok(QueryFunction::QueryValidations),
            0x0A => Ok(QueryFunction::QueryProfiles),
            0x0B => Ok(QueryFunction::QueryCapabilities),
            0x0C => Ok(QueryFunction::QueryClientRegistrationMethods),
            _ => Err(()),
        }
    }
}

impl From<QueryFunction> for u32 {
    fn from(func: QueryFunction) -> Self {
        func as u32
    }
}

bitflags::bitflags! {
    /// Cryptographic Usage Mask (bitflags)
    ///
    /// Indicates allowed cryptographic operations for a key.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CryptographicUsageMask: u32 {
        const SIGN = 0x00000001;
        const VERIFY = 0x00000002;
        const ENCRYPT = 0x00000004;
        const DECRYPT = 0x00000008;
        const WRAP_KEY = 0x00000010;
        const UNWRAP_KEY = 0x00000020;
        const EXPORT = 0x00000040;
        const MAC_GENERATE = 0x00000080;
        const MAC_VERIFY = 0x00000100;
        const DERIVE_KEY = 0x00000200;
        const CONTENT_COMMITMENT = 0x00000400;
        const KEY_AGREEMENT = 0x00000800;
        const CERTIFICATE_SIGN = 0x00001000;
        const CRL_SIGN = 0x00002000;
        const GENERATE_CRYPTOGRAM = 0x00004000;
        const VALIDATE_CRYPTOGRAM = 0x00008000;
        const TRANSLATE_ENCRYPT = 0x00010000;
        const TRANSLATE_DECRYPT = 0x00020000;
        const TRANSLATE_WRAP = 0x00040000;
        const TRANSLATE_UNWRAP = 0x00080000;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_conversion() {
        assert_eq!(Operation::try_from(0x01), Ok(Operation::Create));
        assert_eq!(Operation::try_from(0x0A), Ok(Operation::Get));
        assert_eq!(Operation::try_from(0x12), Ok(Operation::Activate));
        assert_eq!(u32::from(Operation::Encrypt), 0x1F);
    }

    #[test]
    fn test_object_type_conversion() {
        assert_eq!(ObjectType::try_from(0x02), Ok(ObjectType::SymmetricKey));
        assert_eq!(u32::from(ObjectType::PrivateKey), 0x04);
    }

    #[test]
    fn test_algorithm_conversion() {
        assert_eq!(
            CryptographicAlgorithm::try_from(0x03),
            Ok(CryptographicAlgorithm::Aes)
        );
        assert_eq!(u32::from(CryptographicAlgorithm::Rsa), 0x04);
    }

    #[test]
    fn test_result_status_conversion() {
        assert_eq!(ResultStatus::try_from(0x00), Ok(ResultStatus::Success));
        assert_eq!(
            ResultStatus::try_from(0x01),
            Ok(ResultStatus::OperationFailed)
        );
    }

    #[test]
    fn test_key_state_conversion() {
        assert_eq!(KeyState::try_from(0x01), Ok(KeyState::PreActive));
        assert_eq!(KeyState::try_from(0x02), Ok(KeyState::Active));
        assert_eq!(u32::from(KeyState::Destroyed), 0x05);
    }

    #[test]
    fn test_usage_mask_bitflags() {
        let mask = CryptographicUsageMask::SIGN | CryptographicUsageMask::VERIFY;
        assert!(mask.contains(CryptographicUsageMask::SIGN));
        assert!(mask.contains(CryptographicUsageMask::VERIFY));
        assert!(!mask.contains(CryptographicUsageMask::ENCRYPT));
        assert_eq!(mask.bits(), 0x03);
    }
}
