#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "consts.h"
#include "io.h"
#include "libsecurity.h"


int state_sec = 0;
char* hostname = NULL;
EVP_PKEY* priv_key = NULL;
tlv* client_hello = NULL;
tlv* server_hello = NULL;

uint8_t ts[1000] = {0};
uint16_t ts_len = 0;

bool inc_mac = false;

void init_sec(int initial_state, char* host, bool bad_mac) {
    state_sec = initial_state;
    hostname = host;
    inc_mac = bad_mac;
    ts_len = 0;
    memset(ts, 0, sizeof(ts));
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        
        generate_private_key();
        derive_public_key();
        
        client_hello = create_tlv(CLIENT_HELLO);
        
        tlv* nonce_tlv = create_tlv(NONCE);
        add_val(nonce_tlv, nonce, NONCE_SIZE);
        add_tlv(client_hello, nonce_tlv);
        
        tlv* pubkey_tlv = create_tlv(PUBLIC_KEY);
        add_val(pubkey_tlv, public_key, pub_key_size);
        add_tlv(client_hello, pubkey_tlv);
        
        size_t len = serialize_tlv(buf, client_hello);
        
        // CRITICAL: Save to transcript buffer
        memcpy(ts, buf, len);
        ts_len = len;
        
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        
        return len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        // 1. Generate ephemeral keypair for ECDH
        generate_private_key();
        derive_public_key();

        // 2. Get client's ephemeral public key and derive the shared secret
        tlv* client_pubkey_tlv = get_tlv(client_hello, PUBLIC_KEY);
        if (!client_pubkey_tlv || !client_pubkey_tlv->val) {
            exit(6);
        }
        load_peer_public_key(client_pubkey_tlv->val, client_pubkey_tlv->length);

        derive_secret();

        // 3. Load certificate (for including in ServerHello)
        load_certificate("server_cert.bin");
        tlv* cert = deserialize_tlv(certificate, cert_size);

        // 4. Build nonce and public key TLVs
        tlv* nonce_tlv = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        add_val(nonce_tlv, nonce, NONCE_SIZE);

        tlv* public_key_tlv = create_tlv(PUBLIC_KEY);
        add_val(public_key_tlv, public_key, pub_key_size);

        // 5. Load long-term server signing key (now safe to overwrite ec_priv_key)
        load_private_key("server_key.bin");

        // 6. Sign the handshake transcript (ClientHello, nonce, cert, server ephemeral pubkey)
        uint8_t sig_input[2000];
        size_t sig_input_len = 0;
        sig_input_len += serialize_tlv(sig_input, client_hello);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, nonce_tlv);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, cert);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, public_key_tlv);

        uint8_t sig_val[128];
        size_t signature_len = sign(sig_val, sig_input, sig_input_len);

        tlv* signature = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(signature, sig_val, signature_len);

        // 7. Build and send ServerHello
        server_hello = create_tlv(SERVER_HELLO);
        add_tlv(server_hello, nonce_tlv);
        add_tlv(server_hello, cert);
        add_tlv(server_hello, public_key_tlv);
        add_tlv(server_hello, signature);

        ssize_t len = serialize_tlv(buf, server_hello);

        // 8. Derive keys from the already-derived secret + transcript
        uint8_t salt[1500];
        size_t salt_len = 0;
        salt_len += serialize_tlv(salt, client_hello);
        salt_len += serialize_tlv(salt + salt_len, server_hello);
        derive_keys(salt, salt_len);

        state_sec = SERVER_FINISHED_AWAIT;
        return len;
    }
    case CLIENT_FINISHED_SEND: {
        print("SEND FINISHED");
        
        // Use the GLOBAL ts buffer
        uint8_t transcript_hmac[32];
        hmac(transcript_hmac, ts, ts_len);
        
        tlv* transcript_tlv = create_tlv(TRANSCRIPT);
        add_val(transcript_tlv, transcript_hmac, 32);
        
        tlv* finished = create_tlv(FINISHED);
        add_tlv(finished, transcript_tlv);
        
        size_t len = serialize_tlv(buf, finished);
        
        free_tlv(finished);
        state_sec = DATA_STATE;
        
        return len;
    }
    case DATA_STATE: {
        uint8_t plaintext[943];
        ssize_t n = input_io(plaintext, sizeof(plaintext));
        
        if (n <= 0) return 0;
        
        uint8_t iv_val[16];
        uint8_t ciphertext_val[1024];
        size_t ciphertext_len = encrypt_data(iv_val, ciphertext_val, plaintext, n);
        
        tlv* iv = create_tlv(IV);
        add_val(iv, iv_val, 16);
        
        tlv* ciphertext = create_tlv(CIPHERTEXT);
        add_val(ciphertext, ciphertext_val, ciphertext_len);
        
        uint8_t mac_input[2000];
        size_t mac_input_len = 0;
        mac_input_len += serialize_tlv(mac_input, iv);
        mac_input_len += serialize_tlv(mac_input + mac_input_len, ciphertext);
        
        uint8_t mac_val[32];
        hmac(mac_val, mac_input, mac_input_len);
        
        if (inc_mac) {
            mac_val[0] ^= 1;
        }
        
        tlv* mac = create_tlv(MAC);
        add_val(mac, mac_val, 32);
        
        tlv* data = create_tlv(DATA);
        add_tlv(data, iv);
        add_tlv(data, ciphertext);
        add_tlv(data, mac);
        
        ssize_t len = serialize_tlv(buf, data);
        free_tlv(data);
        
        return len;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        client_hello = deserialize_tlv(buf, length);
        if (!client_hello || client_hello->type != CLIENT_HELLO) {
            exit(6);
        }

        // Save client hello to transcript
        tlv* client_pubkey_tlv = get_tlv(client_hello, PUBLIC_KEY);
        if (!client_pubkey_tlv || !client_pubkey_tlv->val) {
            exit(6);
        }
        
        load_peer_public_key(client_pubkey_tlv->val, client_pubkey_tlv->length);
        
        memcpy(ts, buf, length);
        ts_len = length;

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        print("RECEIVED SERVER HELLO");

        server_hello = deserialize_tlv(buf, length);
        if (!server_hello || server_hello->type != SERVER_HELLO) {
            exit(6);
        }

        // Add server_hello to transcript
        memcpy(ts + ts_len, buf, length);
        ts_len += length;

        tlv* nonce         = server_hello->children[0];
        tlv* cert_tlv      = server_hello->children[1];
        tlv* server_pubkey = server_hello->children[2];
        tlv* handshake_sig = server_hello->children[3];

        if (!nonce || !cert_tlv || !server_pubkey || !handshake_sig) {
            exit(6);
        }

        load_ca_public_key("ca_public_key.bin");

        tlv* dns_name       = cert_tlv->children[0];
        tlv* cert_pubkey    = cert_tlv->children[1];
        tlv* lifetime       = cert_tlv->children[2];
        tlv* cert_signature = cert_tlv->children[3];

        if (!dns_name || !cert_pubkey || !lifetime || !cert_signature) {
            exit(1);
        }

        uint8_t cert_data[1000];
        size_t cert_data_len = 0;
        cert_data_len += serialize_tlv(cert_data, dns_name);
        cert_data_len += serialize_tlv(cert_data + cert_data_len, cert_pubkey);
        cert_data_len += serialize_tlv(cert_data + cert_data_len, lifetime);

        if (verify(cert_signature->val, cert_signature->length,
                cert_data, cert_data_len, ec_ca_public_key) != 1) {
            exit(1);
        }

        if (hostname) {
            size_t hostname_len = strlen(hostname);
            if ((dns_name->length != hostname_len && dns_name->length != hostname_len + 1) ||
                memcmp(dns_name->val, hostname, hostname_len) != 0) {
                exit(2);
            }
        }

        if (lifetime->length != 16) {
            exit(1);
        }
        uint64_t not_before, not_after;
        memcpy(&not_before, lifetime->val, 8);
        memcpy(&not_after,  lifetime->val + 8, 8);
        not_before = be64toh(not_before);
        not_after  = be64toh(not_after);

        uint64_t now = (uint64_t)time(NULL);
        if (now < not_before || now > not_after) {
            exit(1);
        }

        load_peer_public_key(cert_pubkey->val, cert_pubkey->length);

        uint8_t sig_input[2000];
        size_t sig_input_len = 0;
        sig_input_len += serialize_tlv(sig_input, client_hello);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, nonce);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, cert_tlv);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, server_pubkey);

        if (verify(handshake_sig->val, handshake_sig->length,
                sig_input, sig_input_len, ec_peer_public_key) != 1) {
            exit(3);
        }

        load_peer_public_key(server_pubkey->val, server_pubkey->length);
        derive_secret();
        
        // Use ts buffer for key derivation
        derive_keys(ts, ts_len);

        state_sec = CLIENT_FINISHED_SEND;
        break;
    }
    case SERVER_FINISHED_AWAIT: {
        print("RECEIVED FINISHED");
        tlv* finished = deserialize_tlv(buf, length);
        
        if (!finished || finished->type != FINISHED) {
            exit(6);
        }
        
        tlv* received_transcript = finished->children[0];
        
        if (!received_transcript) {
            exit(6);
        }
        
        uint8_t transcript_input[1500];
        size_t transcript_input_len = 0;
        transcript_input_len += serialize_tlv(transcript_input, client_hello);
        transcript_input_len += serialize_tlv(transcript_input + transcript_input_len, server_hello);
        
        uint8_t expected_transcript[32];
        hmac(expected_transcript, transcript_input, transcript_input_len);
        
        if (memcmp(received_transcript->val, expected_transcript, 32) != 0) {
            exit(4);
        }
        
        free_tlv(finished);
        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        tlv* data = deserialize_tlv(buf, length);
        
        if (!data || data->type != DATA) {
            exit(6);
        }
        
        tlv* iv = data->children[0];
        tlv* ciphertext = data->children[1];
        tlv* received_mac = data->children[2];
        
        if (!iv || !ciphertext || !received_mac) {
            exit(6);
        }
        
        uint8_t mac_input[2000];
        size_t mac_input_len = 0;
        mac_input_len += serialize_tlv(mac_input, iv);
        mac_input_len += serialize_tlv(mac_input + mac_input_len, ciphertext);
        
        uint8_t expected_mac[32];
        hmac(expected_mac, mac_input, mac_input_len);
        
        if (memcmp(received_mac->val, expected_mac, 32) != 0) {
            exit(5);
        }
        
        uint8_t plaintext[1024];
        size_t plaintext_len = decrypt_cipher(plaintext, ciphertext->val, 
                                             ciphertext->length, iv->val);
        
        output_io(plaintext, plaintext_len);
        
        free_tlv(data);
        break;
    }
    default:
        break;
    }
}