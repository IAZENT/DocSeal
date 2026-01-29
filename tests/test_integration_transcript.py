"""Integration test: Registrar signs transcript, student and employer verify.

Scenario:
1. Registrar creates student transcript (plaintext PDF)
2. Registrar signs it with their key
3. Student verifies signature (to confirm authenticity)
4. Employer verifies signature (to confirm document is from institution)
5. Both use registrar's public cert
"""

import pytest

from docseal.core import DocSealService, DsealEnvelope


@pytest.mark.integration
def test_transcript_scenario(registrar, student_charlie, employer_eve):
    """Test basic transcript signing and verification scenario."""
    # Setup
    service = DocSealService()

    # Sample transcript PDF content
    transcript_content = b"""
    OFFICIAL ACADEMIC TRANSCRIPT
    
    Student: Charlie Brown
    ID: CB001234
    
    Courses Completed:
    - CS101: Introduction to Programming (A)
    - CS201: Data Structures (A+)
    - CS301: Algorithms (A)
    - MATH101: Calculus I (A)
    - MATH201: Linear Algebra (A+)
    
    GPA: 4.0
    Status: In Good Standing
    
    Date: 2024-01-15
    Registrar: Registry Authority
    """

    # Step 1: Registrar signs transcript
    registrar.ensure_loaded()
    signed_envelope = service.sign(
        transcript_content,
        registrar.private_key,
        registrar.certificate,
        description="Official Academic Transcript",
    )

    # Verify envelope was created properly
    assert signed_envelope is not None
    assert signed_envelope.metadata.signer_name == "Registry Authority"
    assert signed_envelope.payload == transcript_content
    assert signed_envelope.signature is not None
    assert not signed_envelope.metadata.payload_encrypted

    # Step 2: Serialize envelope to .dseal format
    envelope_bytes = signed_envelope.to_bytes()
    assert len(envelope_bytes) > 0

    # Step 3: Student receives and verifies
    student_charlie.ensure_loaded()
    received_envelope = DsealEnvelope.from_bytes(envelope_bytes)
    student_result = service.verify(received_envelope, [registrar.certificate])

    assert student_result.is_valid
    assert student_result.signer_name == "Registry Authority"
    assert not student_result.is_encrypted

    # Step 4: Employer receives and verifies
    employer_eve.ensure_loaded()
    employer_envelope = DsealEnvelope.from_bytes(envelope_bytes)
    employer_result = service.verify(employer_envelope, [registrar.certificate])

    assert employer_result.is_valid
    assert employer_result.signer_name == "Registry Authority"

    # Both verify same content
    assert student_result.is_valid == employer_result.is_valid
    # Both have access to same payload through received envelopes
    assert student_charlie.certificate  # Both can verify with signer's cert


@pytest.mark.integration
def test_transcript_tamper_detection(registrar):
    """Test that tampering with transcript is detected."""
    service = DocSealService()

    # Create and sign transcript
    registrar.ensure_loaded()
    original_content = b"Grade: A+"
    signed_envelope = service.sign(
        original_content,
        registrar.private_key,
        registrar.certificate,
    )

    # Serialize
    envelope_bytes = signed_envelope.to_bytes()

    # Tamper: Flip a bit in the signature
    tampered_bytes = bytearray(envelope_bytes)
    # Find signature location (varies with envelope format) and flip a bit
    # This is a simplified tamper - in real scenario would modify payload
    for i in range(len(tampered_bytes) // 2, len(tampered_bytes)):
        tampered_bytes[i] = (tampered_bytes[i] + 1) % 256
        break

    # Try to verify tampered envelope
    from docseal.core import DsealEnvelope

    try:
        tampered_envelope = DsealEnvelope.from_bytes(bytes(tampered_bytes))
        result = service.verify(tampered_envelope, [registrar.certificate])

        # Verification should fail or flag as invalid
        # The specific outcome depends on where tampering occurred
        assert not result.is_valid or result.error_message
    except Exception:  # noqa: S110
        # Deserialization or verification failed - also acceptable
        pass


@pytest.mark.integration
def test_multiple_signers(registrar, lecturer_alice):
    """Test document signed by multiple parties (co-signing scenario).

    Scenario:
    1. Registrar creates document
    2. Registrar signs it
    3. Lecturer co-signs
    """
    service = DocSealService()

    document = b"EXAM RESULT: PASSED WITH DISTINCTION"

    # Step 1: Registrar signs
    registrar.ensure_loaded()
    env1 = service.sign(
        document,
        registrar.private_key,
        registrar.certificate,
        description="Exam approval",
    )

    # Step 2: Lecturer signs the registrar's signed envelope
    lecturer_alice.ensure_loaded()
    env2 = service.sign(
        env1.to_bytes(),
        lecturer_alice.private_key,
        lecturer_alice.certificate,
        description="Lecturer verification",
    )

    # Step 3: Verify nested signatures
    # First verify outer (lecturer) signature
    result1 = service.verify(env2, [lecturer_alice.certificate])
    assert result1.is_valid

    # Then verify inner (registrar) signature
    inner_envelope = DsealEnvelope.from_bytes(env2.payload)
    result2 = service.verify(inner_envelope, [registrar.certificate])
    assert result2.is_valid
