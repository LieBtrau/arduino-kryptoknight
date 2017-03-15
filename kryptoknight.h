#ifndef KRYPTOKNIGHT_H
#define KRYPTOKNIGHT_H

#include "Arduino.h"
#include "aes-cbc-cmac.h"

//The transmission protocol should insert source and destination fields in the messages.  These are needed for authentication.
class Kryptoknight
{
public:
    typedef struct
    {
        byte* value;
        byte length;
    }ID;
    typedef int (*RNG_Function)(uint8_t *dest, unsigned size);
    static byte getNonceSize();
    static byte getMacSize();
    byte getPayloadSize();
    Kryptoknight();
    void getLocalNonce(byte* nonce);
    byte getLocalId(byte* destination);
    void getMacab(byte *macOut);
    void getMacba(byte *macOut);
    byte* getPayload();
    void getPayload(byte* destination);
    void setInitiator(bool isInitiator);
    void setLocalId(byte* localId, byte idLength);
    bool setRemoteInfo(byte* remoteId, byte idLength, byte* key);
    void setRemoteNonce(byte* nonce);
    bool setPayload(const byte* payload, byte payloadLength);
    void generateLocalNonce(RNG_Function rng_function);
    bool isValidMacab(byte* macIn);
    bool isValidMacba(byte* macIn);
    bool isValidRemoteInfo();
    void reset();
private:
    static const byte MAX_PAYLOAD_LENGTH=64;
    static const byte NONCE_LENGTH=8;
    static const byte KEY_LENGTH=16;//key for 128bit CMAC
    ID  _localID;
    ID _remoteID;
    byte _localNonce[NONCE_LENGTH];
    byte _remoteNonce[NONCE_LENGTH];
    byte _payload[MAX_PAYLOAD_LENGTH];
    byte _payloadLength;
    byte* _sharedKey;
    bool _isRemoteInfoValid;
    bool _bIsInitiator;
};

#endif // KRYPTOKNIGHT_H
