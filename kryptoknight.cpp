//This code is based on the authentication protocol described in:
// P.Janson, G.Tsudik, M.Yung, "Scalability and Flexibility in Authentication Services: The Kryptoknight Approach," Proc. IEEE Infocom 97, Kobe, Japan (Apr 97).

#include "kryptoknight.h"
//#define DEBUG
#ifdef DEBUG
extern void print(const byte* array, byte length);
#endif

Kryptoknight::Kryptoknight(const byte *localId, byte idLength,
                           RNG_Function rng_function, TX_Function tx_func, RX_Function rx_func):
    Kryptoknight(rng_function, tx_func, rx_func)
{
    setLocalId(localId, idLength);
}

Kryptoknight::Kryptoknight(RNG_Function rng_function,
                           TX_Function tx_func, RX_Function rx_func):
    _rng_function(rng_function),
    _txfunc(tx_func),
    _rxfunc(rx_func),
    _rxedEvent(0),
    _commTimeOut(0),
    _sharedKey(0)
{
    _messageBuffer=(byte*)malloc(255);
    if(!_messageBuffer)
    {
#ifdef DEBUG
        Serial.println("Can't init.");
#endif
    }
    _state=WAITING_FOR_NONCE_A;
}

bool Kryptoknight::setLocalId(const byte* localId, byte idLength)
{
    _idLength=idLength;
    _localID=(byte*) malloc(_idLength);
    if(!_localID)
    {
        return false;
    }
    memcpy(_localID, localId, _idLength);
    _remoteID=(byte*) malloc(_idLength);
    return true;
}

void  Kryptoknight::setSharedKey(byte* key)
{
    if(key[0]!=key[1] && key[1]!=key[2])
    {
        _sharedKey=key;
    }
}


//Prepare initiator message = TAG | NONCE(A) | PAYLOAD
bool Kryptoknight::sendMessage(const byte* remoteId, const byte* payload, byte payloadLength)
{
    if(payloadLength > MAX_PAYLOAD_LENGTH)
    {
#ifdef DEBUG
        Serial.println("Payload too long.");
#endif
        return false;
    }
    _rng_function(_nonce_A,NONCE_LENGTH);
    _payloadLength=payloadLength;
    memcpy(_payload, payload, _payloadLength);
    memcpy(_remoteID, remoteId, _idLength);
    *_messageBuffer=NONCE_A;
    memcpy(_messageBuffer+1, _nonce_A, NONCE_LENGTH);
    memcpy(_messageBuffer+1+NONCE_LENGTH, payload, payloadLength);
    if(!_txfunc(_messageBuffer,1+NONCE_LENGTH+payloadLength))
    {
#ifdef DEBUG
        Serial.println("Can't send initiator message.");
#endif
        return false;
    }
    _id_A=_localID;
    _id_B=_remoteID;
    _state=WAITING_FOR_NONCE_B;
    _commTimeOut=millis();
    return true;
}

void Kryptoknight::setMessageReceivedHandler(EventHandler rxedEvent)
{
    _rxedEvent=rxedEvent;
}



Kryptoknight::AUTHENTICATION_RESULT Kryptoknight::loop()
{
    byte messageLength;
    if(millis()>_commTimeOut+10000)
    {
#ifdef DEBUG
        Serial.println("Timeout");
#endif
        _state=WAITING_FOR_NONCE_A;
        _commTimeOut=millis();
    }
    messageLength=255;
    if(!_rxfunc(&_messageBuffer, messageLength) || !messageLength)
    {
        if(!messageLength)
        {
#ifdef DEBUG
            Serial.println("Empty message.");
#endif
        }
        return _state==WAITING_FOR_NONCE_A ? NO_AUTHENTICATION: AUTHENTICATION_BUSY;
    }
    if(!_sharedKey)
    {
#ifdef DEBUG
        Serial.println("No valid key");
#endif
        _state==WAITING_FOR_NONCE_A;
        return NO_AUTHENTICATION;
    }
#ifdef DEBUG
    else
    {
        Serial.print("Shared key: ");
        print(_sharedKey, 16);
    }
#endif
    switch(_state)
    {
    case WAITING_FOR_NONCE_A:   //Remote peer waiting for message = TAG | NONCE(A) | PAYLOAD
        _id_A=_remoteID;
        _id_B=_localID;
        if(*_messageBuffer!=NONCE_A)
        {
#ifdef DEBUG
            Serial.println("Message is not NONCE_A.");
#endif
            return NO_AUTHENTICATION;
        }
        //Get parameters from incoming message
        memcpy(_nonce_A, _messageBuffer+1, NONCE_LENGTH);
        _payloadLength=messageLength-1-NONCE_LENGTH;
        memcpy(_payload, _messageBuffer+1+NONCE_LENGTH, _payloadLength);
        //Prepare 2nd message in protocol = TAG | MACba(NA|PAYLOAD|NB|B) | NB
        *_messageBuffer=NONCE_B;
        _rng_function(_nonce_B,NONCE_LENGTH);
        calcMacba(_messageBuffer+1);
        memcpy(_messageBuffer+1+KEY_LENGTH, _nonce_B, NONCE_LENGTH);
#ifdef DEBUG
        Serial.println("NONCE_A correctly received.");
#endif
        if(_txfunc(_messageBuffer,1+KEY_LENGTH+NONCE_LENGTH))
        {
#ifdef DEBUG
            Serial.println("2nd message in protocol sent.");
#endif
            _state=WAITING_FOR_MAC_NAB;
            _commTimeOut=millis();
            return AUTHENTICATION_BUSY;
        }
#ifdef DEBUG
        Serial.println("Can't send 2nd message in protocol");
#endif
        _state=WAITING_FOR_NONCE_A;
        return NO_AUTHENTICATION;
    case WAITING_FOR_NONCE_B:   //Initiator waiting for message = TAG | MACba(NA|PAYLOAD|NB|B) | NB
        if(*_messageBuffer!=NONCE_B)
        {
#ifdef DEBUG
            Serial.println("Message is not NONCE_B");
#endif
            _state=WAITING_FOR_NONCE_A;
            return NO_AUTHENTICATION;
        }
        //Getting parameters from message: TAG | MACba(NA|PAYLOAD|NB|B) | NB
        memcpy(_nonce_B,_messageBuffer+1+KEY_LENGTH,NONCE_LENGTH);
        if(!isValidMacba((byte*)_messageBuffer+1))
        {
#ifdef DEBUG
            Serial.println("MAC_BA is invalid");
#endif
            _state=WAITING_FOR_NONCE_A;
            return NO_AUTHENTICATION;
        }
#ifdef DEBUG
        Serial.println("MAC_BA is valid");
#endif
        //Prepare 3rd message in protocol: TAG | MACab(NA | NB)
        *_messageBuffer=MAC_NAB;
        calcMacab(_messageBuffer+1);
        _state=WAITING_FOR_NONCE_A;
#ifdef DEBUG
        Serial.println("MAC_NAB is sent");
#endif
        return _txfunc(_messageBuffer,1+KEY_LENGTH) ? AUTHENTICATION_AS_INITIATOR_OK : NO_AUTHENTICATION;
    case WAITING_FOR_MAC_NAB://Remote peer waiting for message = TAG | MACab(NA | NB)
        _state=WAITING_FOR_NONCE_A;
        //Check incoming message
        if((*_messageBuffer!=MAC_NAB) || (!isValidMacab((byte*)_messageBuffer+1)))
        {
#ifdef DEBUG
            Serial.println("MAC_NAB not correctly received");
#endif
            return NO_AUTHENTICATION;
        }
        if(_rxedEvent)
        {
            _rxedEvent(_payload, _payloadLength);
        }
#ifdef DEBUG
        Serial.println("MAC_NAB successfully received");
#endif
        return AUTHENTICATION_AS_PEER_OK;
    }
}

bool Kryptoknight::isValidMacba(byte* macIn)
{
    byte* buffer=(byte*)malloc(KEY_LENGTH);
    calcMacba(buffer);
    bool bResult= !memcmp(buffer, macIn, KEY_LENGTH);
    free(buffer);
    return bResult;
}

bool Kryptoknight::isValidMacab(byte* macIn)
{
    byte* buffer=(byte*)malloc(KEY_LENGTH);
    calcMacab(buffer);
    bool bResult= !memcmp(buffer, macIn, KEY_LENGTH);
    free(buffer);
    return bResult;
}

//MACba(NA | PAYLOAD | NB | B)
void Kryptoknight::calcMacba(byte* macOut)
{
    byte* buffer=(byte*)malloc(NONCE_LENGTH*2+_payloadLength+_idLength);
    byte* pBuf=buffer;
    memcpy(pBuf, _nonce_A, NONCE_LENGTH);
    pBuf+=NONCE_LENGTH;
    memcpy(pBuf, _payload, _payloadLength);
    pBuf+=_payloadLength;
    memcpy(pBuf, _nonce_B, NONCE_LENGTH);
    pBuf+=NONCE_LENGTH;
    memcpy(pBuf, _id_B, _idLength);
    pBuf+=_idLength;
    AES_CMAC(_sharedKey, buffer, pBuf-buffer , macOut);
    free(buffer);
}

//MACab(NA | NB)
void Kryptoknight::calcMacab(byte* macOut)
{
    byte bufferLength=NONCE_LENGTH*2;
    byte* buffer=(byte*)malloc(bufferLength);
    memcpy(buffer, _nonce_A, NONCE_LENGTH);
    memcpy(buffer+NONCE_LENGTH, _nonce_B, NONCE_LENGTH);
    AES_CMAC(_sharedKey, buffer, bufferLength, macOut);
    free(buffer);
}
