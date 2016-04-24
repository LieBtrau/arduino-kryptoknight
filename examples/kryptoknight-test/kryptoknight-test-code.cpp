#include "kryptoknight.h"

static int RNG(uint8_t *dest, unsigned size);
void print(const byte* array, byte length);

const byte IDLENGTH=10;
byte id1[IDLENGTH]={0,1,2,3,4,5,6,7,8,9};
byte id2[IDLENGTH]={9,8,7,6,5,4,3,2,1,0};
byte sharedkey[16]={0xA,0xB,0xC,0xD,
                    0xE,0xF,0xE,0xD,
                    0xC,0xB,0xA,0x9,
                    0x8,0x7,0x6,0x5};
byte payload[4]={0xFE, 0xDC, 0xBA, 0x98};
byte commBuff[100];
byte commLength;
Kryptoknight k1= Kryptoknight(Kryptoknight::INITIATOR, id1, IDLENGTH, sharedkey, &RNG);
Kryptoknight k2= Kryptoknight(Kryptoknight::PEER, id2, IDLENGTH, sharedkey, &RNG);


void setup() {
    // put your setup code here, to run once:
    Serial.begin(115200);
    Serial.println("start");
    Serial.println("Initiator starts authentication");
    if(!k1.initAuthentication(id2,payload,4,commBuff, commLength))
    {
        Serial.println("Can't initialize authenticaton.");
        return;
    }
    Serial.println("Initiator message = TAG | NONCE(A) | PAYLOAD");
    print(commBuff,commLength);
    Serial.println("-");
    if(k2.processAuthentication(commBuff,commLength,commBuff,commLength)!=Kryptoknight::AUTHENTICATION_BUSY)
    {
        Serial.println("Peer doesn't understand the message.");
        return;
    }
    Serial.println("Peer message = TAG | MACba(NA|PAYLOAD|NB|B) | NB");
    print(commBuff,commLength);
    Serial.println("-");
    if(k1.processAuthentication(commBuff,commLength,commBuff,commLength)!=Kryptoknight::AUTHENTICATION_OK)
    {
        Serial.println("Initiator doesn't understand the message from the peer.");
        return;
    }
    Serial.println("Authentication is ok for the initiator. \r\n2nd message from initiator = TAG | MACab(NA | NB)");
    print(commBuff,commLength);
    Serial.println("-");
    if(k2.processAuthentication(commBuff,commLength,commBuff,commLength)!=Kryptoknight::AUTHENTICATION_OK)
    {
        Serial.println("Peer doesn't understand the last message from the initiator.");
        return;
    }
    Serial.println("Authentication is ok for peer too.\r\nInitiator and peer are successfully authenticated.");

}

void loop() {
  // put your main code here, to run repeatedly:

}

//TODO: replace by safe external RNG
static int RNG(uint8_t *dest, unsigned size) {
    // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
    // random noise). This can take a long time to generate random data if the result of analogRead(0)
    // doesn't change very frequently.
    while (size) {
        uint8_t val = 0;
        for (unsigned i = 0; i < 8; ++i) {
            int init = analogRead(0);
            int count = 0;
            while (analogRead(0) == init) {
                ++count;
            }

            if (count == 0) {
                val = (val << 1) | (init & 0x01);
            } else {
                val = (val << 1) | (count & 0x01);
            }
        }
        *dest = val;
        ++dest;
        --size;
    }
    // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
    return 1;
}

void print(const byte* array, byte length)
{
  Serial.print("Length = ");Serial.println(length,DEC);
    for (byte i = 0; i < length; i++)
    {
        Serial.print(array[i], HEX);
        Serial.print(" ");
        if ((i + 1) % 16 == 0)
        {
            Serial.println();
        }
    }
    Serial.println();
}

