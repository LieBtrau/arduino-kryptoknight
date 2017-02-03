#include "kryptoknight.h"

static int RNG(uint8_t *dest, unsigned size);
void print(const byte* array, byte length);

void dataReceived(byte* data, byte length)
{
    Serial.println("Event received with the following data:");
    print(data, length);
}

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
Kryptoknight k1= Kryptoknight(id1,IDLENGTH,sharedkey, &RNG, writeData1, readData1);
Kryptoknight k2= Kryptoknight(id2,IDLENGTH,sharedkey, &RNG, writeData2, readData2);

void setup() {
    // put your setup code here, to run once:
    Serial.begin(9600);
    Serial.println("start");
    k2.setMessageReceivedHandler(dataReceived);
    Serial.println("Initiator starts authentication");
    if(!k1.sendMessage(id2,payload,4))
    {
	Serial.println("Sending message failed.");
	return;
    }
}

void loop() {
    if(k1.loop()==Kryptoknight::AUTHENTICATION_AS_INITIATOR_OK)
    {
	Serial.println("Message received by peer and acknowledged");
    }
    if(k2.loop()==Kryptoknight::AUTHENTICATION_AS_PEER_OK)
    {
	Serial.println("Message received by remote initiator");
    }
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

//Dummy send and receive functions.
//Should be replaced by Serial write and read functions in real application
static byte rxtxData[100];
static byte rxtxLength;
static bool dataReady=false;
static byte rxtxData2[100];
static byte rxtxLength2;
static bool dataReady2=false;


//Dummy function to write data from device 2 to device 1
bool writeData2(byte* data, byte length)
{
    memcpy(rxtxData,data, length);
    rxtxLength=length;
    dataReady=true;
    Serial.print("Data written by device 2 to device 1: ");print(data, length);
    return true;
}

//Dummy function to read incoming data on device 1
bool readData1(byte* &data, byte& length)
{
    if(!dataReady)
    {
    return false;
    }
    dataReady=false;
    data=rxtxData;
    length=rxtxLength;
    Serial.print("Data read by device 1: ");print(data, length);
    return true;
}


//Dummy function to write data from device 1 to device 2
bool writeData1(byte* data, byte length)
{
    memcpy(rxtxData2,data, length);
    rxtxLength2=length;
    dataReady2=true;
    Serial.print("Data written by device 1 to device 2: ");print(data, length);
    return true;
}

//Dummy function to read incoming data on device 2
bool readData2(byte* &data, byte& length)
{
    if(!dataReady2)
    {
    return false;
    }
    dataReady2=false;
    data=rxtxData2;
    length=rxtxLength2;
    Serial.print("Data read by device 2: ");print(data, length);
    return true;
}
