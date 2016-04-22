//This code is based on the authentication protocol described in:
// P.Janson, G.Tsudik, M.Yung, "Scalability and Flexibility in Authentication Services: The Kryptoknight Approach," Proc. IEEE Infocom 97, Kobe, Japan (Apr 97).

#include "kryptoknight.h"

kryptoknight::kryptoknight(AUTHENTICATION_ROLE role, byte* localId, byte idLength, byte* sharedkey):
    _role(role),
    _idLength(idLength)
{
    if(_role==INITIATOR)
    {
        _id_A=(byte*) malloc(_idLength);
        memcpy(_id_A, localId, _idLength);
        _state=NOT_STARTED;
    }else
    {
        _id_B=(byte*) malloc(_idLength);
        memcpy(_id_B, localId, _idLength);
        _state=WAITING_FOR_NONCE_A;
    }
    memcpy(_sharedKey, sharedkey, KEY_LENGTH);
}

//Prepare initiator message = TAG | NONCE(A) | PAYLOAD
bool kryptoknight::initAuthentication(const byte* id_B, const byte* payload, byte payloadLength, byte* messageOut, byte& messagelength)
{
    if(_role!=INITIATOR || payloadLength > MAX_PAYLOAD_LENGTH)
    {
        return false;
    }
    _rng_function(_nonce_A,NONCE_LENGTH);
    _payloadLength=payloadLength;
    memcpy(_payload, payload, _payloadLength);
    _id_B=(byte*) malloc(_idLength);
    memcpy(_id_B, id_B, _idLength);

    byte* pMsg=messageOut;
    *pMsg++=NONCE_A;
    memcpy(pMsg, _nonce_A, NONCE_LENGTH);
    pMsg+=NONCE_LENGTH;
    memcpy(pMsg, payload, payloadLength);
    pMsg+=payloadLength;
    messagelength=pMsg-messageOut;
    _state=WAITING_FOR_NONCE_B;
    return true;
}

kryptoknight::AUTHENTICATION_RESULT kryptoknight::processAuthentication(const byte* messageBufferIn, byte messagelengthIn,
        byte* payloadOut, byte &payloadlengthOut)
{
    payloadlengthOut=0;
    byte *pPayload=payloadOut;

    if(_role==INITIATOR)
    {
        if(_state != WAITING_FOR_NONCE_B || messageBufferIn[0] != NONCE_B)
        {
            _state=NOT_STARTED;
            return NO_AUTHENTICATION;
        }
        //Getting parameters from message: TAG | MAC(NA|PAYLOAD|NB|B) | NB
        memcpy(_nonce_B,messageBufferIn+1+KEY_LENGTH,NONCE_LENGTH);
        if(!isValidMacba((byte*)messageBufferIn+1))
        {
            _state=NOT_STARTED;
            return NO_AUTHENTICATION;
        }
        *pPayload++=MAC_NAB;
        calcMacab(pPayload);
        payloadlengthOut=1+KEY_LENGTH;
        _state=NOT_STARTED;
        return AUTHENTICATION_OK;
    }else
    {
        //Peer role
        switch(_state)
        {
        case WAITING_FOR_NONCE_A:
            if(messageBufferIn[0]!=NONCE_A)
            {
                _state=NOT_STARTED;
                return NO_AUTHENTICATION;
            }
            //Get parameters from incoming message
            memcpy(_nonce_A, messageBufferIn+1, NONCE_LENGTH);
            _payloadLength=messagelengthIn-1-NONCE_LENGTH;
            memcpy(_payload, messageBufferIn+1+NONCE_LENGTH, _payloadLength);
            _rng_function(_nonce_B,NONCE_LENGTH);
            //Prepare 2nd message in protocol = TAG | MAC(NA|PAYLOAD|NB|B) | NB
            *pPayload++=NONCE_B;
            calcMacba(pPayload);
            pPayload+=KEY_LENGTH;
            memcpy(pPayload, _nonce_B, NONCE_LENGTH);
            pPayload+=NONCE_LENGTH;
            payloadlengthOut=pPayload-payloadOut;
            _state=WAITING_FOR_MAC_NAB;
            return AUTHENTICATION_BUSY;
        case WAITING_FOR_MAC_NAB:
            _state=NOT_STARTED;
            return (messageBufferIn[0]!=MAC_NAB) || (!isValidMacab((byte*)messageBufferIn+1)) ? NO_AUTHENTICATION : AUTHENTICATION_OK;
        default:
             _state=NOT_STARTED;
            return NO_AUTHENTICATION;
        }
    }
}

bool kryptoknight::isValidMacba(byte* macIn)
{
    byte* buffer=(byte*)malloc(KEY_LENGTH);
    calcMacba(buffer);
    bool bResult= !memcmp(buffer, macIn, KEY_LENGTH);
    free(buffer);
    return bResult;
}

bool kryptoknight::isValidMacab(byte* macIn)
{
    byte* buffer=(byte*)malloc(KEY_LENGTH);
    calcMacab(buffer);
    bool bResult= !memcmp(buffer, macIn, KEY_LENGTH);
    free(buffer);
    return bResult;
}

//MACba(NA | PAYLOAD | NB | B)
void kryptoknight::calcMacba(byte* macOut)
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
void kryptoknight::calcMacab(byte* macOut)
{
    byte bufferLength=NONCE_LENGTH*2;
    byte* buffer=(byte*)malloc(bufferLength);
    memcpy(buffer, _nonce_A, NONCE_LENGTH);
    memcpy(buffer+NONCE_LENGTH, _nonce_B, NONCE_LENGTH);
    AES_CMAC(_sharedKey, buffer, bufferLength, macOut);
    free(buffer);
}
