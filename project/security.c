#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "consts.h"
#include "io.h"
#include "libsecurity.h"

int state_sec = 0;     // Current state for handshake
char* hostname = NULL; // For client: storing inputted hostname
EVP_PKEY* priv_key = NULL;
tlv* client_hello = NULL;
tlv* server_hello = NULL;

uint8_t ts[1000] = {0};
uint16_t ts_len = 0;

bool inc_mac = false;  // For testing only: send incorrect MACs

void init_sec(int initial_state, char* host, bool bad_mac) {
    state_sec = initial_state;
    hostname = host;
    inc_mac = bad_mac;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        //generate client ephemeral key pair 
        generate_private_key();
        derive_public_key();
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
        //load server private key and cert
        load_private_key("server_key.bin");
        load_certificate("server_cert.bin");
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        //create nonce 
        tlv* nonce = create_tlv(NONCE);
        uint8_t nonce_val[32];
        generate_nonce(nonce_val, 32);
        add_val(nonce, nonce_val, 32);

        //create public key tlv 
        tlv* pubkey = create_tlv(PUBLIC_KEY);
        add_val(pubkey, public_key, pub_key_size);

        //create client hello
        client_hello = create_tlv(CLIENT_HELLO);
        add_tlv(client_hello, nonce);
        add_tlv(client_hello, pubkey);

        ssize_t len = serialize_tlv(buf, client_hello);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        //create nonce 
        tlv* nonce = create_tlv(NONCE);
        uint8_t nonce_val[32];
        generate_nonce(nonce_val, 32);
        add_val(nonce, nonce_val, 32);

        //create cert tlv 
        tlv* cert = create_tlv(CERTIFICATE);
        add_val(cert, certificate, cert_size);

        //generate ephemeral key pair and save old key 
        EVP_PKEY* old_key = get_private_key();
        generate_private_key();
        derive_public_key();
        EVP_PKEY* ephemeral_key = get_private_key();

        //create ephemeral public key tlv 
        tlv* ephemeral_pubkey = create_tlv(PUBLIC_KEY);
        add_val(ephemeral_pubkey, public_key, pub_key_size);

        //build server hello
        server_hello = create_tlv(SERVER_HELLO);
        add_tlv(server_hello, nonce);
        add_tlv(server_hello, cert);
        add_tlv(server_hello, ephemeral_pubkey);

        //create signature over 
        uint8_t sig_input[2000];
        size_t sig_input_len = 0;
        sig_input_len += serialize_tlv(sig_input, client_hello);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, nonce);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, cert);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, ephemeral_pubkey);

        //sign with server's private key 
        set_private_key(old_key);
        uint8_t sig_val[80];
        size_t sig_len = sign(sig_val, sig_input, sig_input_len);

        tlv* signature = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(signature, sig_val, sig_len);

        //add signature to server hello
        add_tlv(server_hello, signature);

        //serialize 
        ssize_t len = serialize_tlv(buf, server_hello);

        // Restore ephemeral key for DH
        set_private_key(ephemeral_key);
        
        // Derive keys
        uint8_t salt[1500];
        size_t salt_len = 0;
        salt_len += serialize_tlv(salt, client_hello);
        salt_len += serialize_tlv(salt + salt_len, server_hello);
        
        // Get client's public key from client_hello
        tlv* client_pubkey_tlv = get_tlv(client_hello, PUBLIC_KEY);
        load_peer_public_key(client_pubkey_tlv->val, client_pubkey_tlv->length);
        
        derive_secret();
        derive_keys(salt, salt_len);
        
        EVP_PKEY_free(old_key);
        
        state_sec = SERVER_FINISHED_AWAIT;
        return len;
    }
    case CLIENT_FINISHED_SEND: {
        print("SEND FINISHED");

        // Create transcript: HMAC of (client_hello + server_hello)
        uint8_t transcript_input[1500];
        size_t transcript_input_len = 0;
        transcript_input_len += serialize_tlv(transcript_input, client_hello);
        transcript_input_len += serialize_tlv(transcript_input + transcript_input_len, server_hello);
        
        uint8_t transcript_val[32];
        hmac(transcript_val, transcript_input, transcript_input_len);
        
        tlv* transcript = create_tlv(TRANSCRIPT);
        add_val(transcript, transcript_val, 32);
        
        // Build Finished message
        tlv* finished = create_tlv(FINISHED);
        add_tlv(finished, transcript);
        
        ssize_t len = serialize_tlv(buf, finished);
        
        free_tlv(finished);
        state_sec = DATA_STATE;
        return len;        
    }
    case DATA_STATE: {
        // Read from stdin
        uint8_t plaintext[943]; // Max plaintext size
        ssize_t n = input_io(plaintext, sizeof(plaintext));
        
        if (n <= 0) return 0;
        
        // Encrypt (generates IV internally)
        uint8_t iv_val[16];
        uint8_t ciphertext_val[1024];
        size_t ciphertext_len = encrypt_data(iv_val, ciphertext_val, plaintext, n);
        
        tlv* iv = create_tlv(IV);
        add_val(iv, iv_val, 16);
        
        tlv* ciphertext = create_tlv(CIPHERTEXT);
        add_val(ciphertext, ciphertext_val, ciphertext_len);
        
        // Compute MAC over IV + Ciphertext (with TLV headers)
        uint8_t mac_input[2000];
        size_t mac_input_len = 0;
        mac_input_len += serialize_tlv(mac_input, iv);
        mac_input_len += serialize_tlv(mac_input + mac_input_len, ciphertext);
        
        uint8_t mac_val[32];
        hmac(mac_val, mac_input, mac_input_len);
        
        // Optionally corrupt MAC for testing
        if (inc_mac) {
            mac_val[0] ^= 1;
        }
        
        tlv* mac = create_tlv(MAC);
        add_val(mac, mac_val, 32);
        
        // Build Data message
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
            fprintf(stderr, "invalid client hello");
            exit(6);
        }

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        print("RECEIVED SERVER HELLO");
        server_hello = deserialize_tlv(buf, length);
        
        if (!server_hello || server_hello->type != SERVER_HELLO) {
            fprintf(stderr, "Invalid Server Hello\n");
            exit(6);
        }
        
        // Extract components using children array
        tlv* nonce = server_hello->children[0];
        tlv* cert_tlv = server_hello->children[1];
        tlv* server_pubkey = server_hello->children[2];
        tlv* handshake_sig = server_hello->children[3];
        
        // Parse certificate (it's a TLV containing nested TLVs)
        tlv* certificate = deserialize_tlv(cert_tlv->val, cert_tlv->length);
        
        // Load CA public key
        load_ca_public_key("ca_public_key.bin");

        // Certificate structure: DNS-Name, Public-Key, Lifetime, Signature
        tlv* dns_name = certificate->children[0];
        tlv* cert_pubkey = certificate->children[1];
        tlv* lifetime = certificate->children[2];
        tlv* cert_signature = certificate->children[3];
        
        // Build what was signed: DNS-Name || Public-Key || Lifetime
        uint8_t cert_data[1000];
        size_t cert_data_len = 0;
        cert_data_len += serialize_tlv(cert_data, dns_name);
        cert_data_len += serialize_tlv(cert_data + cert_data_len, cert_pubkey);
        cert_data_len += serialize_tlv(cert_data + cert_data_len, lifetime);
        
        // Verify certificate signature
        if (verify(cert_signature->val, cert_signature->length, 
                   cert_data, cert_data_len, ec_ca_public_key) != 1) {
            fprintf(stderr, "Certificate verification failed\n");
            exit(1);
        }

        //  Verify DNS name
        if (hostname) {
            size_t hostname_len = strlen(hostname);
            if (dns_name->length != hostname_len || 
                memcmp(dns_name->val, hostname, hostname_len) != 0) {
                fprintf(stderr, "DNS name mismatch\n");
                exit(2);
            }
        }
        
        // Check certificate validity
        uint64_t not_before, not_after;
        memcpy(&not_before, lifetime->val, 8);
        memcpy(&not_after, lifetime->val + 8, 8);
        not_before = be64toh(not_before);
        not_after = be64toh(not_after);
        uint64_t now = time(NULL);
        
        if (now < not_before || now > not_after) {
            fprintf(stderr, "Certificate expired or not yet valid\n");
            exit(1);
        }
        // Verify Server Hello signature
        load_peer_public_key(cert_pubkey->val, cert_pubkey->length);
        
        // Build what was signed: client_hello || nonce || cert_tlv || server_pubkey
        uint8_t sig_input[2000];
        size_t sig_input_len = 0;
        sig_input_len += serialize_tlv(sig_input, client_hello);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, nonce);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, cert_tlv);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, server_pubkey);
        
        if (verify(handshake_sig->val, handshake_sig->length,
                   sig_input, sig_input_len, ec_peer_public_key) != 1) {
            fprintf(stderr, "Handshake signature verification failed\n");
            exit(3);
        }

        // Derive keys
        load_peer_public_key(server_pubkey->val, server_pubkey->length);
        derive_secret();
        
        uint8_t salt[1500];
        size_t salt_len = 0;
        salt_len += serialize_tlv(salt, client_hello);
        salt_len += serialize_tlv(salt + salt_len, server_hello);
        
        derive_keys(salt, salt_len);
        
        free_tlv(certificate);
        state_sec = CLIENT_FINISHED_SEND;
        break;
    }
    case SERVER_FINISHED_AWAIT: {
        print("RECEIVED FINISHED");
        tlv* finished = deserialize_tlv(buf, length);
        
        if (!finished || finished->type != FINISHED) {
            fprintf(stderr, "Invalid Finished message\n");
            exit(6);
        }
        
        // Verify transcript
        tlv* received_transcript = finished->children[0];
        
        // Compute expected transcript
        uint8_t transcript_input[1500];
        size_t transcript_input_len = 0;
        transcript_input_len += serialize_tlv(transcript_input, client_hello);
        transcript_input_len += serialize_tlv(transcript_input + transcript_input_len, server_hello);
        
        uint8_t expected_transcript[32];
        hmac(expected_transcript, transcript_input, transcript_input_len);
        
        if (memcmp(received_transcript->val, expected_transcript, 32) != 0) {
            fprintf(stderr, "Transcript verification failed\n");
            exit(4);
        }
        
        free_tlv(finished);
        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        tlv* data = deserialize_tlv(buf, length);
        
        if (!data || data->type != DATA) {
            fprintf(stderr, "Invalid Data message\n");
            exit(6);
        }
        
        // Extract IV, Ciphertext, MAC using children array
        tlv* iv = data->children[0];
        tlv* ciphertext = data->children[1];
        tlv* received_mac = data->children[2];
        
        // Verify MAC
        uint8_t mac_input[2000];
        size_t mac_input_len = 0;
        mac_input_len += serialize_tlv(mac_input, iv);
        mac_input_len += serialize_tlv(mac_input + mac_input_len, ciphertext);
        
        uint8_t expected_mac[32];
        hmac(expected_mac, mac_input, mac_input_len);
        
        if (memcmp(received_mac->val, expected_mac, 32) != 0) {
            fprintf(stderr, "MAC verification failed\n");
            exit(5);
        }
        
        // Decrypt
        uint8_t plaintext[1024];
        size_t plaintext_len = decrypt_cipher(plaintext, ciphertext->val, 
                                             ciphertext->length, iv->val);
        
        // Write to stdout
        output_io(plaintext, plaintext_len);
        
        free_tlv(data);
        break;
    }
    default:
        break;
    }
}