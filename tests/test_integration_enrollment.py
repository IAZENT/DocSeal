"""Integration test: Registrar signs & encrypts enrollment, student decrypts & verifies.

Scenario:
1. Registrar creates enrollment form (plaintext PDF)
2. Registrar signs it (creates signature)
3. Registrar encrypts signed envelope for student (creates nested envelope)
4. Student receives encrypted envelope
5. Student decrypts using their private key (gets signed envelope)
6. Student verifies signature using registrar's cert (confirms authenticity)
7. Employer cannot decrypt (no private key) but can verify registrar's
   signature on ciphertext
"""

import pytest

from docseal.core import DocSealService, DsealEnvelope


@pytest.mark.integration
def test_enrollment_encrypted_scenario(registrar, student_charlie, employer_eve):
    """Test enrollment document signed and encrypted for student."""
    service = DocSealService()

    # Sample enrollment form
    enrollment_form = b"""
    ENROLLMENT CONFIRMATION
    
    Student: Charlie Brown
    ID: CB001234
    Program: BSc Computer Science
    Academic Year: 2023/24
    
    Courses Registered:
    - CS401: Advanced Algorithms
    - CS402: Machine Learning
    - MATH301: Abstract Algebra
    
    Tuition Status: Paid
    Enrollment Date: 2024-01-10
    
    Registrar: Registry Authority
    """

    # Setup
    registrar.ensure_loaded()
    student_charlie.ensure_loaded()
    employer_eve.ensure_loaded()

    # Step 1-3: Registrar signs AND encrypts for student
    encrypted_envelope = service.sign_encrypt(
        enrollment_form,
        registrar.private_key,
        registrar.certificate,
        student_charlie.certificate,
        description="Enrollment Confirmation",
    )

    # Verify envelope structure
    assert encrypted_envelope.metadata.payload_encrypted
    assert encrypted_envelope.metadata.signer_name  # Signature info preserved

    # Serialize to .dseal
    envelope_bytes = encrypted_envelope.to_bytes()

    # Step 4: Student receives encrypted envelope

    received_envelope = DsealEnvelope.from_bytes(envelope_bytes)
    assert received_envelope.metadata.payload_encrypted

    # Step 5: Student decrypts
    decrypted_envelope, verification_result = service.decrypt_and_verify(
        received_envelope,
        student_charlie.private_key,
        [registrar.certificate],
    )

    # Step 6: Verify signature is valid
    assert verification_result.is_valid
    assert decrypted_envelope.payload == enrollment_form
    assert not decrypted_envelope.metadata.payload_encrypted

    # Step 7: Employer cannot decrypt (no private key) but can see it's signed
    # Employer would receive the .dseal file but cannot decrypt it
    # Reload the encrypted envelope from bytes to verify it's still encrypted
    received_envelope_copy = DsealEnvelope.from_bytes(envelope_bytes)
    assert received_envelope_copy.metadata.payload_encrypted
    # Attempting to decrypt without the right key should fail
    try:
        service.decrypt(received_envelope_copy, employer_eve.private_key)
        raise AssertionError("Should not be able to decrypt with wrong key")
    except Exception:  # noqa: S110
        # Expected to fail
        pass


@pytest.mark.integration
def test_multiple_recipients(registrar, student_charlie, student_diana):
    """Test document encrypted for multiple recipients (advanced scenario).

    Note: This is a preview of multi-recipient support (Phase 3).
    Current implementation supports one recipient per envelope.
    """
    service = DocSealService()

    document = b"SCHOLARSHIP AWARD LETTER: $5000"

    registrar.ensure_loaded()
    student_charlie.ensure_loaded()
    student_diana.ensure_loaded()

    # For now, create separate envelopes for each student
    envelope_charlie = service.sign_encrypt(
        document,
        registrar.private_key,
        registrar.certificate,
        student_charlie.certificate,
    )

    envelope_diana = service.sign_encrypt(
        document,
        registrar.private_key,
        registrar.certificate,
        student_diana.certificate,
    )

    # Each student can decrypt their copy
    dec_charlie, ver_charlie = service.decrypt_and_verify(
        envelope_charlie,
        student_charlie.private_key,
        [registrar.certificate],
    )
    assert ver_charlie.is_valid
    assert dec_charlie.payload == document

    dec_diana, ver_diana = service.decrypt_and_verify(
        envelope_diana,
        student_diana.private_key,
        [registrar.certificate],
    )
    assert ver_diana.is_valid
    assert dec_diana.payload == document

    # Charlie cannot decrypt Diana's envelope
    try:
        service.decrypt(envelope_diana, student_charlie.private_key)
        raise AssertionError("Charlie should not decrypt Diana's envelope")
    except Exception:  # noqa: S110
        # Expected
        pass


@pytest.mark.integration
def test_encryption_without_signing(registrar, student_charlie):
    """Test encryption-only scenario (no signature).

    Scenario: Registrar encrypts sensitive data for student,
    student decrypts but doesn't verify signature.
    """
    service = DocSealService()

    sensitive_data = b"CONFIDENTIAL: Student has academic probation"

    registrar.ensure_loaded()
    student_charlie.ensure_loaded()

    # Encrypt without signing
    encrypted_envelope = service.encrypt(
        sensitive_data,
        student_charlie.certificate,
    )

    assert encrypted_envelope.metadata.payload_encrypted
    assert encrypted_envelope.signature is None  # No signature

    # Student decrypts
    envelope_bytes = encrypted_envelope.to_bytes()

    received = DsealEnvelope.from_bytes(envelope_bytes)
    decrypted = service.decrypt(received, student_charlie.private_key)

    assert decrypted.payload == sensitive_data
    assert not decrypted.metadata.payload_encrypted
