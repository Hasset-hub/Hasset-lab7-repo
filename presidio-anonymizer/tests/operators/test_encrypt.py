from unittest import mock

import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError

import pytest

@pytest.mark.parametrize("key", [
    # String keys - 128, 192, and 256 bits
    "1234567890123456",                    # 128 bits (16 bytes)
    "123456789012345678901234",            # 192 bits (24 bytes) 
    "12345678901234567890123456789012",    # 256 bits (32 bytes)
    # Bytes keys - 128, 192, and 256 bits  
    b'1234567890123456',                   # 128 bits (16 bytes)
    b'123456789012345678901234',           # 192 bits (24 bytes)
    b'12345678901234567890123456789012',   # 256 bits (32 bytes)
])
def test_valid_keys(key):
    """Test that validate succeeds for valid key sizes (128, 192, 256 bits)."""
    from presidio_anonymizer.operators.encrypt import Encrypt
    
    encrypt = Encrypt()
    # This should not raise an exception for valid keys
    encrypt.validate({"key": key})

    
@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

@mock.patch('cryptography.hazmat.primitives.ciphers.algorithms.AES')
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_aes):
    """Test that validate raises an error for invalid key length."""
    # Make AES key validation fail
    mock_aes.side_effect = ValueError("Invalid key length")
    
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})

def test_operator_name():
    from presidio_anonymizer.operators import Encrypt
    op = Encrypt()
    assert op.operator_name() == "encrypt"

def test_operator_type():
    from presidio_anonymizer.operators import OperatorType
    from presidio_anonymizer.operators import Encrypt
    op = Encrypt()
    assert op.operator_type() == OperatorType.Anonymize