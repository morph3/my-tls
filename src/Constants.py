class Context:
    TLS_VERSION = b"\x03\x03" # tls v1.2
    TLS_VERSION_1_2 = b"\x03\x03" # tls v1.2
    TLS_VERSION_1_1 = b"\x03\x02" # tls v1.1

    CIPHER_SUITES = {
        "TLS_AES_256_GCM_SHA384": 0x1302,
        "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
        "TLS_AES_128_GCM_SHA256": 0x1301,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xc02c,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 0xc030,
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": 0x009f,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca9,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca8,
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xccaa,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xc02b,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 0xc02f,
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": 0x009e,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": 0xc024,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": 0xc028,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": 0x006b,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 0xc023,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": 0xc027,
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": 0x0067,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": 0xc00a,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": 0xc014,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": 0x0039,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": 0xc009,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 0xc013,
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": 0x0033,
        "TLS_RSA_WITH_AES_256_GCM_SHA384": 0x009d,
        "TLS_RSA_WITH_AES_128_GCM_SHA256": 0x009c,
        "TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003d,
        "TLS_RSA_WITH_AES_128_CBC_SHA256": 0x003c,
        "TLS_RSA_WITH_AES_256_CBC_SHA": 0x0035,
        "TLS_RSA_WITH_AES_128_CBC_SHA": 0x002f,
        "LS_EMPTY_RENEGOTIATION_INFO_SCSV": 0x00ff
    }
        
    ZERO_EXTENSION = False

    if 0:
        CN = "morph3.blog"
        IP = "35.209.169.119"
        PORT = 443
    else:
        CN = "localhost"
        IP = "127.0.0.1"
        PORT = 8443

    SERVER_CERTIFICATES = []
    SERVER_PUBLIC_KEY = b""
    SERVER_PUBLIC_KEY_PEM = ""
    SERVER_PUBLIC_KEY_DER = ""

    RECEIVED_MSGS = {}
    AGGREED_CIPHER_SUITE = ""
    HANDSHAKE_MESSAGES = b""

    SERVER_PARAMS = {}
    PMS = ""
    KEYS = {}
    ENCRYPT_RECORDS = False
    SEQ_NUM = 0  # legacy single counter (no longer used for MAC)
    READ_SEQ = 0
    WRITE_SEQ = 0
    # Buffer for encrypted records received before keys are ready
    PENDING_ENCRYPTED_RECORDS = b""
    # Storage for latest Finished verify_data parsed by parser
    LAST_FINISHED_VERIFY_DATA = b""
    MASTER_SECRET = b""
    IS_GCM = False
    CIPHER_NAME = ""
    SERVER_RANDOM_TIME_STAMP = b""
    SERVER_RANDOM = None
    CLIENT_RANDOM = None
    IS_SERVER = False
    # Storage for last seen Alert (level, description)
    LAST_ALERT = None

    def get_cipher_suite_name_from_bytes(self, byte):
        for name, value in self.CIPHER_SUITES.items():
            if value == int.from_bytes(byte, byteorder='big'):
                return name
        return "Unknown"