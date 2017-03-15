#include "kryptoknightcomm.h"



KryptoKnightComm::KryptoKnightComm(byte *localId, byte idLength,
                                   RNG_Function rng_function, TX_Function tx_func, RX_Function rx_func):
    KryptoKnightComm(rng_function, tx_func, rx_func)
{
    init(localId, idLength);
}

KryptoKnightComm::KryptoKnightComm(RNG_Function rng_function, TX_Function tx_func, RX_Function rx_func):
    _rng_function(rng_function),
    _txfunc(tx_func),
    _rxfunc(rx_func),
    _rxedEvent(0),
    _idRxedEvent(0),
    _commTimeOut(0),
    _krypto(),
    _state(WAITING_FOR_ID_B)
{
    _messageBuffer=(byte*)malloc(255);
    if(!_messageBuffer)
    {
#ifdef DEBUG
        Serial.println("Can't init.");
#endif
    }
}

bool KryptoKnightComm::init(byte* localId, byte idLength)
{
    _krypto.setLocalId(localId, idLength);
}

bool KryptoKnightComm::setRemoteParty(byte* remoteId, byte idLength, byte* sharedKey)
{
    return _krypto.setRemoteInfo(remoteId, idLength, sharedKey);
}

KryptoKnightComm::AUTHENTICATION_RESULT KryptoKnightComm::loop()
{
    byte messageLength;
    if(millis()>_commTimeOut+10000)
    {
#ifdef DEBUG
        Serial.println("Timeout");
#endif
        _state=WAITING_FOR_ID_B;
        _commTimeOut=millis();
    }
    messageLength=255;
    if(!_rxfunc(&_messageBuffer, messageLength) || !messageLength)
    {
        return _state==WAITING_FOR_ID_B ? NO_AUTHENTICATION: AUTHENTICATION_BUSY;
    }
    switch(_state)
    {
    case WAITING_FOR_ID_B:
        _krypto.reset();
        if(parseIdB(messageLength) && sendNonceA())
        {
            _state=WAITING_FOR_NONCE_B;
            _commTimeOut=millis();
            return AUTHENTICATION_BUSY;
        }
        break;
    case WAITING_FOR_NONCE_A:
        if(parseNonceA() && sendNonceB())
        {
            _state=WAITING_FOR_MAC_NAB;
            return AUTHENTICATION_BUSY;
        }
        _state=WAITING_FOR_ID_B;
        return NO_AUTHENTICATION;
    case WAITING_FOR_NONCE_B:
        _state=WAITING_FOR_ID_B;
        return (parseNonceB(messageLength) && sendMacNab()) ? AUTHENTICATION_AS_INITIATOR_OK : NO_AUTHENTICATION;
    case WAITING_FOR_MAC_NAB:
        _state=WAITING_FOR_ID_B;
        if(parseMacNab())
        {
#ifdef DEBUG
            Serial.println("MAC_NAB successfully received");
#endif
            if(_rxedEvent)
            {
                _rxedEvent(_krypto.getPayload(), _krypto.getPayloadSize());
            }
            return AUTHENTICATION_AS_PEER_OK;
        }
        return NO_AUTHENTICATION;
    }
}

void KryptoKnightComm::setMessageReceivedHandler(EventHandler rxedEvent)
{
    _rxedEvent=rxedEvent;
}

void KryptoKnightComm::setKeyRequestHandler(EventHandler rxedEvent)
{
    _idRxedEvent=rxedEvent;
}

//Prepare initiator message = TAG | ID(B)
bool KryptoKnightComm::sendMessage(const byte* payload, byte payloadLength,
                                   byte* remoteId, byte idLength, byte* sharedKey)
{
    if(!_krypto.setPayload(payload, payloadLength))
    {
        return false;
    }
    setRemoteParty(remoteId, idLength, sharedKey);
    *_messageBuffer=ID_B;
    if(!_txfunc(_messageBuffer,1+_krypto.getLocalId(_messageBuffer+1)))
    {
#ifdef DEBUG
        Serial.println("Can't send initiator message.");
#endif
        return false;
    }
    _krypto.setInitiator(true);
    _state=WAITING_FOR_NONCE_A;
    _commTimeOut=millis();
    return true;
}

//TAG | ID(B)
bool KryptoKnightComm::parseIdB(byte messageLength)
{
    if(*_messageBuffer!=ID_B)
    {
#ifdef DEBUG
        Serial.println("Message is not ID_B.");
#endif
        return false;
    }
    if(!_idRxedEvent)
    {
#ifdef DEBUG
        Serial.println("No ID message handler set.");
#endif
        return false;
    }
    //Signal the event with the received ID(B).  The eventhandler should react by passing the shared key and id to this object.
    _idRxedEvent(_messageBuffer+1, messageLength-1);
    return _krypto.isValidRemoteInfo();
}

bool KryptoKnightComm::sendNonceA()
{
    *_messageBuffer=NONCE_A;
    _krypto.generateLocalNonce(_rng_function);
    _krypto.getLocalNonce(_messageBuffer+1);
    if(!_txfunc(_messageBuffer, 1+_krypto.getNonceSize()))
    {
#ifdef DEBUG
        Serial.println("Can't send NONCE_A message.");
#endif
        return false;
    }
    return true;
}

bool KryptoKnightComm::parseNonceA()
{
    if(*_messageBuffer!=NONCE_A)
    {
#ifdef DEBUG
        Serial.println("Message is not NONCE_A.");
#endif
        return false;
    }
    _krypto.setRemoteNonce(_messageBuffer+1);
    return true;
}

bool KryptoKnightComm::sendNonceB()
{
    //Prepare 2nd message in protocol = TAG | NB | PAYLOAD  | MACba(NA|PAYLOAD|NB|B)
    *_messageBuffer=NONCE_B;
    _krypto.generateLocalNonce(_rng_function);
    byte* ptr=_messageBuffer+1;
    _krypto.getLocalNonce(ptr);
    ptr+=_krypto.getNonceSize();
    _krypto.getPayload(ptr);
    ptr+=_krypto.getPayloadSize();
    _krypto.getMacba(ptr);
    ptr+=_krypto.getMacSize();
    if(!_txfunc(_messageBuffer,ptr-_messageBuffer))
    {
#ifdef DEBUG
        Serial.println("Can't send NONCE_B message.");
#endif
        return false;
    }
    return true;
}

bool KryptoKnightComm::parseNonceB(byte messageLength)
{
    if(*_messageBuffer!=NONCE_B)
    {
#ifdef DEBUG
        Serial.println("Message is not NONCE_B");
#endif
        return false;
    }
    //Getting parameters from message: TAG | NB | PAYLOAD  | MACba(NA|PAYLOAD|NB|B)
    byte* ptr=_messageBuffer+1;
    _krypto.setRemoteNonce(ptr);
    ptr+=_krypto.getNonceSize();
    _krypto.setPayload(ptr,messageLength-1-_krypto.getNonceSize()-_krypto.getMacSize());
    ptr+=_krypto.getPayloadSize();
    if(!_krypto.isValidMacba(ptr))
    {
#ifdef DEBUG
        Serial.println("MAC_BA is invalid");
#endif
        return false;
    }
    return true;
}

bool KryptoKnightComm::sendMacNab()
{
    //Prepare 3rd message in protocol: TAG | MACab(NA | NB)
    *_messageBuffer=MAC_NAB;
    _krypto.getMacab(_messageBuffer+1);
    return _txfunc(_messageBuffer,1+_krypto.getMacSize());
}

bool KryptoKnightComm::parseMacNab()
{
    return (*_messageBuffer==MAC_NAB) && _krypto.isValidMacab((byte*)_messageBuffer+1);
}
