#ifndef KRYPTOKNIGHTCOMM_H
#define KRYPTOKNIGHTCOMM_H

#include "kryptoknight.h"

class KryptoKnightComm
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
    KryptoKnightComm(RNG_Function rng_function, TX_Function tx_func, RX_Function rx_func);
    KryptoKnightComm(byte *localId, byte idLength, RNG_Function rng_function, TX_Function tx_func, RX_Function rx_func);
    AUTHENTICATION_RESULT loop();
    bool init(byte* localId, byte idLength);
    bool setRemoteParty(byte* remoteId, byte idLength, byte* sharedKey);
    bool sendMessage(const byte* payload, byte payloadLength, byte *remoteId, byte idLength, byte *sharedKey);
    void setMessageReceivedHandler(EventHandler rxedEvent);
    void setKeyRequestHandler(EventHandler idRxedEvent);
    void reset();
private:
    typedef enum
    {
        ID_B,
        NONCE_A,
        NONCE_B,
        MAC_NAB
    }MSG_ID;
    typedef enum
    {
        NOT_STARTED,
        WAITING_FOR_ID_B,
        WAITING_FOR_NONCE_A,
        WAITING_FOR_NONCE_B,
        WAITING_FOR_MAC_NAB,
    }AUTHENTICATION_STATE;
    bool parseIdB(byte messageLength);
    bool sendNonceA();
    bool parseNonceA();
    bool sendNonceB();
    bool parseNonceB(byte messageLength);
    bool sendMacNab();
    bool parseMacNab();
    RNG_Function _rng_function;
    TX_Function _txfunc;
    RX_Function _rxfunc;
    EventHandler _rxedEvent;
    EventHandler _idRxedEvent;
    AUTHENTICATION_STATE _state;
    unsigned long _commTimeOut;
    byte* _messageBuffer;
    Kryptoknight _krypto;
};

#endif // KRYPTOKNIGHTCOMM_H
