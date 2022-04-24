
# arduino-kryptoknight
Arduino library for two-way authentication between two parties that share a common secret key.

There's an option to piggyback a message to the protocol, which limits the number of packets to be sent.

## Protocol messages 
Used terms:
* A : identity of party A
* B : identity of party B
* Na : nonce generated by A
* Nb : nonce generated by B
* MACab : message authentication code created with key that is shared with A & B, i.e. AES-CMAC.

Messages:
 1. A <- B : B
 2. A -> B : Na
 3. A <- B : Nb | PAYLOAD | MACab( Na | PAYLOAD | Nb | B )
 4. Optional : A -> B : MACab(Na | Nb)     

A is considered as the party that controls access to a certain resource.  B is a device that must be trusted before its data is being accepted by the resource.

 - B lets A know that it wants to send some payload by transmitting its ID.  
 - A responds by sending a fresh random nonce Na.  
 - It's up to B now to send its payload, together with a MAC, calculated over the shared secret key, the nonce Na, its payload, a nonce Nb -that B has generated- and B's identity.  When A receives this message, it checks validity of the MAC.  If ok, then B is authenticated by A and the payload is accepted and passed on to the resource.
 - If two way authentication is needed, A needs to send back a MAC calculated over the shared secret key and both nonces.  Upon arrival of this message at B, the MAC is checked.  If the MAC is valid, then B knows for sure that it was A that has correctly received the message.
# References
 - [IBM Kryptoknight 2PAP](http://books.google.be/books?id=GEz1sYwz494C&lpg=PA167&ots=PPK7nyTvQf&dq=2PAKDP&pg=PA166#v=onepage&q=2PAKDP&f=false)
 - P. Janson, G. Tsudik, M. Yung, "Scalability and Flexibility in Authentication services: The Kryptoknight Approach"
 - R. Molva, G. Tsudik, E. Van Herreweghen, S. Zatti: "Kryptoknight Authentication and Key Distribution System"
 - R. Bird, I. Gopal, A. Herzberg, P. Janson, S. Kutten, R. Molva, M. Yung:"The Kryptoknight Family of Light-Weight Protocols for Authentication and Key Distribution"


