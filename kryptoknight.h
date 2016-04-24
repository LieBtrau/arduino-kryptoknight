#ifndef KRYPTOKNIGHT_H
#define KRYPTOKNIGHT_H

#include "Arduino.h"
//git clone git@github.com:LieBtrau/AES-CMAC-RFC.git ~/git/aes-cmac-rfc
//ln -s ~/git/aes-cmac-rfc/ ~/Arduino/libraries/
#include "cmac.h"

//The transmission protocol should insert source and destination fields in the messages.  These are needed for authentication.
class Kryptoknight
{
public:
    typedef int (*RNG_Function)(uint8_t *dest, unsigned size);
    typedef enum
    {
        NO_AUTHENTICATION,
        AUTHENTICATION_OK,
        AUTHENTICATION_BUSY,
    }AUTHENTICATION_RESULT;
    typedef enum
    {
        INITIATOR,
        PEER
    }AUTHENTICATION_ROLE;
    Kryptoknight(AUTHENTICATION_ROLE role, byte *localId, byte idLength, byte *sharedkey, RNG_Function rng_function);
    bool initAuthentication(const byte *id_B, const byte* payload, byte payloadLength, byte* messageOut, byte& messagelength);
    AUTHENTICATION_RESULT processAuthentication(const byte* messageBufferIn, byte messagelengthIn,
                                                byte* payloadOut, byte& payloadlengthOut);
private:
    typedef enum
    {
        NONCE_A,
        NONCE_B,
        MAC_NAB
    }MSG_ID;
    typedef enum
    {
        NOT_STARTED,
        WAITING_FOR_NONCE_A,
        WAITING_FOR_NONCE_B,
        WAITING_FOR_MAC_NAB,
    }AUTHENTICATION_STATE;
    static const byte MAX_PAYLOAD_LENGTH=64;
    static const byte NONCE_LENGTH=8;
    static const byte KEY_LENGTH=16;//key for 128bit CMAC
    void calcMacba(byte *macOut);
    void calcMacab(byte *macOut);
    bool isValidMacba(byte* macIn);
    bool isValidMacab(byte* macIn);
    RNG_Function _rng_function;
    AUTHENTICATION_STATE _state;
    AUTHENTICATION_ROLE _role;
    byte* _id_A;
    byte* _id_B;
    byte _idLength;
    byte _nonce_A[NONCE_LENGTH];
    byte _nonce_B[NONCE_LENGTH];
    byte _payload[MAX_PAYLOAD_LENGTH];
    byte _payloadLength;
    byte _sharedKey[KEY_LENGTH];
};

#endif // KRYPTOKNIGHT_H
