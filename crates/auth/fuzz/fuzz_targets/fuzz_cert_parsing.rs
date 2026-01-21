#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_auth::mtls::cert_validator::CertificateValidator;

fuzz_target!(|data: &[u8]| {
    // Test certificate parsing functions with arbitrary data
    // These should never panic, only return errors for invalid input

    // Test DER certificate parsing functions
    let _ = CertificateValidator::extract_common_name(data);
    let _ = CertificateValidator::extract_organization(data);
    let _ = CertificateValidator::extract_organizational_unit(data);
    let _ = CertificateValidator::get_serial_number(data);
});
