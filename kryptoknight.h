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
    typedef bool(*TX_Function)(byte* data, byte length);
    typedef bool(*RX_Function)(byte** data, byte& length);
    typedef void(*EventHandler)(byte* data, byte length);

    typedef enum
    {
        NO_AUTHENTICATION,
        AUTHENTICATION_AS_INITIATOR_OK,
        AUTHENTICATION_AS_PEER_OK,
        AUTHENTICATION_BUSY,
    }AUTHENTICATION_RESULT;
    typedef enum
    {
        INITIATOR,
        PEER
    }AUTHENTICATION_ROLE;
    Kryptoknight(const byte *localId, byte idLength, const byte *sharedkey, RNG_Function rng_function,
                 TX_Function tx_func, RX_Function rx_func);
    AUTHENTICATION_RESULT loop();
    bool sendMessage(const byte* remoteId, const byte* payload, byte payloadLength);
    void setMessageReceivedHandler(EventHandler rxedEvent);
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
    TX_Function _txfunc;
    RX_Function _rxfunc;
    EventHandler _rxedEvent;
    AUTHENTICATION_STATE _state;
    AUTHENTICATION_ROLE _role;
    byte* _localID;
    byte* _remoteID;
    byte* _id_A;
    byte* _id_B;
    byte _idLength;
    byte _nonce_A[NONCE_LENGTH];
    byte _nonce_B[NONCE_LENGTH];
    byte _payload[MAX_PAYLOAD_LENGTH];
    byte _payloadLength;
    byte _sharedKey[KEY_LENGTH];
    unsigned long _commTimeOut;
};

#endif // KRYPTOKNIGHT_H
