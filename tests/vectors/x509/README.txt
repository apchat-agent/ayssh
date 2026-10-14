Artificial, self-signed RSA-2048 certificate and independent SHA-1 signature vector.
No real host certificate or private key is included. Generated for this lane using:

openssl req -x509 -newkey rsa:2048 -keyout TEMP_KEY -outform DER -out rsa2048.der -days 3650 -nodes -subj '/CN=ayssh RFC6187 test vector'
printf 'ayssh RFC 6187 exchange hash test vector' > message.bin
openssl dgst -sha1 -sign TEMP_KEY -out signature.bin message.bin

The temporary private key was deleted immediately after generating the signature.
The certificate's validity and self-signature are not used as a CA trust decision.
