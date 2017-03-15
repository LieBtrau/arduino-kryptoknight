//This code is based on the authentication protocol described in:
// P.Janson, G.Tsudik, M.Yung, "Scalability and Flexibility in Authentication Services: The Kryptoknight Approach," Proc. IEEE Infocom 97, Kobe, Japan (Apr 97).

#include "kryptoknight.h"
#define DEBUG
#ifdef DEBUG
extern void print(const byte* array, byte length);
#endif

Kryptoknight::Kryptoknight()
{
    reset();
}

byte Kryptoknight::getLocalId(byte *destination)
{
    memcpy(destination, _localID.value, _localID.length);
    return _localID.length;
}

byte Kryptoknight::getMacSize()
{
    return KEY_LENGTH;
}

byte Kryptoknight::getNonceSize()
{
    return NONCE_LENGTH;
}

byte* Kryptoknight::getPayload()
{
    return _payload;
}

void Kryptoknight::getPayload(byte* destination)
{
    if(_payload && _payloadLength <=MAX_PAYLOAD_LENGTH)
    {
        memcpy(destination, _payload, _payloadLength);
    }
}

byte Kryptoknight::getPayloadSize()
{
    return _payloadLength;
}


void Kryptoknight::setInitiator(bool isInitiator)
{
    _bIsInitiator=isInitiator;
}

void Kryptoknight::setLocalId(byte* localId, byte idLength)
{
    _localID.length=idLength;
    _localID.value=localId;
}

void Kryptoknight::getLocalNonce(byte* nonce)
{
    memcpy(nonce, _localNonce, NONCE_LENGTH);
}

bool Kryptoknight::setPayload(const byte* payload, byte payloadLength)
{
    if(payloadLength > MAX_PAYLOAD_LENGTH)
    {
#ifdef DEBUG
        Serial.println("Payload too long.");
#endif
        return false;
    }
    _payloadLength=payloadLength;
    memcpy(_payload, payload, _payloadLength);
    return true;
}

bool Kryptoknight::setRemoteInfo(byte* remoteId, byte idLength, byte* key)
{
    _remoteID.length=idLength;
    _remoteID.value=remoteId;
    if(key[0]!=key[1] && key[1]!=key[2])
    {
        _sharedKey=key;
        _isRemoteInfoValid=true;
        return true;
    }
    return false;
}

void Kryptoknight::setRemoteNonce(byte* nonce)
{
    memcpy(_remoteNonce, nonce, NONCE_LENGTH);
}

void Kryptoknight::generateLocalNonce(RNG_Function rng_function)
{
    rng_function(_localNonce, NONCE_LENGTH);
}

bool Kryptoknight::isValidMacba(byte* macIn)
{
    byte* buffer=(byte*)malloc(KEY_LENGTH);
    getMacba(buffer);
    bool bResult= !memcmp(buffer, macIn, KEY_LENGTH);
    free(buffer);
    return bResult;
}

bool Kryptoknight::isValidRemoteInfo()
{
    return _isRemoteInfoValid;
}

bool Kryptoknight::isValidMacab(byte* macIn)
{
    byte* buffer=(byte*)malloc(KEY_LENGTH);
    getMacab(buffer);
    bool bResult= !memcmp(buffer, macIn, KEY_LENGTH);
    free(buffer);
    return bResult;
}

//MACba(NA | PAYLOAD | NB | B)
void Kryptoknight::getMacba(byte* macOut)
{
    byte idLength=_bIsInitiator ? _remoteID.length : _localID.length;
    byte* buffer=(byte*)malloc(NONCE_LENGTH*2+_payloadLength + idLength);
    byte* pBuf=buffer;
    memcpy(pBuf, _bIsInitiator ? _localNonce : _remoteNonce, NONCE_LENGTH);
    pBuf+=NONCE_LENGTH;
    memcpy(pBuf, _payload, _payloadLength);
    pBuf+=_payloadLength;
    memcpy(pBuf, _bIsInitiator ? _remoteNonce : _localNonce, NONCE_LENGTH);
    pBuf+=NONCE_LENGTH;
    memcpy(pBuf, _bIsInitiator ? _remoteID.value : _localID.value, idLength);
    pBuf+=idLength;
    AES_CMAC(_sharedKey, buffer, pBuf-buffer , macOut);
    free(buffer);
}

//MACab(NA | NB)
void Kryptoknight::getMacab(byte* macOut)
{
    byte bufferLength=NONCE_LENGTH*2;
    byte* buffer=(byte*)malloc(bufferLength);
    memcpy(buffer,  _bIsInitiator ? _localNonce : _remoteNonce, NONCE_LENGTH);
    memcpy(buffer+NONCE_LENGTH,  _bIsInitiator ? _remoteNonce : _localNonce, NONCE_LENGTH);
    AES_CMAC(_sharedKey, buffer, bufferLength, macOut);
    free(buffer);
}

void Kryptoknight::reset()
{
    _remoteID.length=0;
    _remoteID.value=0;
    memset(_localNonce, 0, sizeof(_localNonce));
    memset(_remoteNonce, 0, sizeof(_remoteNonce));
    memset(_payload, 0, sizeof(_payload));
    _payloadLength=0;
    _sharedKey=0;
    _bIsInitiator=false;
    _isRemoteInfoValid=false;
}
