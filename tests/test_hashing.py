from amiweak.hashing import sha1_hex


def test_known_vector():
    assert sha1_hex("password") == "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"


def test_output_is_lowercase_hex_of_length_40():
    digest = sha1_hex("hunter2")
    assert len(digest) == 40
    assert digest == digest.lower()
    assert all(c in "0123456789abcdef" for c in digest)


def test_unicode_is_utf8_encoded():
    assert sha1_hex("pässwörd") == sha1_hex("pässwörd")


def test_empty_string_hashes():
    assert sha1_hex("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
