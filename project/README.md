# CS 118 Fall 25 Project 2

Contributors: Sneha Agarwal, Vivek Garg, Suhani Shukla

The goal of Project 2 is to implement a TLS-like authenticated key exchange. All security messages follow TLV format. 

For the client hello, the client generates an ephemeral EC key pair and 32-byte nonce. It builds a nonce and ephemeral public key wrapped inside a client-hello TLV. The client serailizes and stores the full TLV to use in server-hello signature verification, salt, and finished transcript HMAC.  

On receiving the client hello, the server generates its own nonce and wraps the raw CA-signed certificate bytes from server_cert.bin inside a certificate TLV. It then generates an ephemeral EC key pair distinct from its certicate key and creates a handshake signature over Client-Hello || Server-Nonce || Certificate || Ephemeral-Server-PubKey using the long-term server private key. It constructs a server hello containing the nonce, certicate, ephemeral public key, and handshake signature. 

For client certificate verification, we parsed the TLV stream manually and compared the certificate's DNS directly to the hostname argument. We converted the 16-byte lifetime field into two big-endian timestamps and perform lifetime checks. 

After both sides load each other's ephemeral public key we call derive_secret and use HKDF to get the ENC and MAC keys. The salt = client hello || server hello, ensuring both sides get identical symmetric keys. 

The client sends Transcript = HMAC(client hello || server hello) and the server recomputes it and aborts on mismatch. 

For outgoing data, we generate a fresh IV, encrypt plaintext, compute HMAC over TLV(IV) || TLV(Ciphertext), construct the data TLV. For incoming data, we validate the MAC first and decrypt after. 

Our implementation mirrors a simplified TLS handshake with ephemeral keys for forward secrecy, certificate and signatures for identity, HKDF for key separation, AES and HMAC for authenticated encryption, and strict TLV ordering. 

A problem we encountered was with formatting the Server Hello. We were having issues of the Server Hello being in an unrecognized form dueto incorrect TLV handling. Our initial solution was causing the certificate's internal structure to become malformed. We incorrectly tried to rebuilt the certificate TLV ourselves, which made its binary layout different from the CA-signed version. Due to this, the server hello was not getting recognized and certificate signature verification was failing. In addition, when the certificate TLV was malformed, the serialized certificate TLV pushed into the signature input was also malformed and server signature verification was failing on the client. 

We solved this by directly TLV-decoding the certificate file. This worked since the provided certificate was already encoded as a TLV sequence and preserved the correct byte structure. Since client-side parsing relies on TLV children, this also fixed issues we were having with accessing dns_name, lifetime, and other children arrays. In addition, once the certificate TLV matched the real TLV structure from the certificate file, the signature input became correct and our handshake tests passed.  
