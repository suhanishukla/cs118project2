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
        generate_private_key();
        derive_public_key();
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        client_hello = create_tlv(CLIENT_HELLO);
        tlv* nonce_tlv = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];     
        add_val(nonce_tlv, nonce, NONCE_SIZE);
        add_tlv(client_hello, nonce_tlv);

        tlv* public_key_tlv = create_tlv(PUBLIC_KEY);
        add_val(public_key_tlv, public_key, pub_key_size);
        add_tlv(client_hello, public_key_tlv);

        
        size_t len = serialize_tlv(buf, client_hello);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        // create nonce tlv
        tlv* nonce_tlv = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE]; 
        generate_nonce(nonce, NONCE_SIZE);
        add_val(nonce_tlv, nonce, NONCE_SIZE);
        

        // create cert
        tlv* cert = create_tlv(CERTIFICATE);
        add_val(cert, certificate, cert_size);

        // create ephemeral public key pair
        EVP_PKEY* old_key = get_private_key();
        generate_private_key();
        derive_public_key();
        EVP_PKEY* eph_key = get_private_key();

        // tlv for public key
        tlv* public_key_tlv = create_tlv(PUBLIC_KEY);
        add_val(public_key_tlv, public_key, pub_key_size);

        // create signature over nonce
        uint8_t sig_input[2000];
        size_t sig_input_len = 0;
        sig_input_len += serialize_tlv(sig_input, client_hello);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, nonce_tlv);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, cert);
        sig_input_len += serialize_tlv(sig_input + sig_input_len, public_key_tlv);

        set_private_key(old_key); 
        uint8_t sig_val[128];
        size_t signature_len = sign(sig_val, sig_input, sig_input_len);
        set_private_key(eph_key);
        
        // tlv for signature
        tlv* signature = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(signature, sig_val, signature_len);

        // create server hello
        server_hello = create_tlv(SERVER_HELLO);
        add_tlv(server_hello, nonce_tlv);
        add_tlv(server_hello, cert);
        add_tlv(server_hello, public_key_tlv);
        add_tlv(server_hello, signature);

        ssize_t len = serialize_tlv(buf, server_hello);

        set_private_key(eph_key);



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
    }
    case DATA_STATE: {
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
    }
    case SERVER_FINISHED_AWAIT: {
    }
    case DATA_STATE: {
        tlv* data = deserialize_tlv(buf, length);
    }
    default:
        break;
    }
}