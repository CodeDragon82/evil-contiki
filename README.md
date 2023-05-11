# Evil Contiki: The OS to attack 6LoWPAN networks.

This is a modified version of the Contiki-ng OS that allows a malicious actor to perform RPL attacks against a 6LowPAN network. These attacks include:
* Blackhole Attack
* Selective Forwarding
* Rank Decrease Attack
* Version Increase Attack
* DIS Flooding

These attacks can be controlled with the 'attacker shell' which is defined in `examples/attacker`. This can be compiled and uploaded to nrf52840 USB dongle or other Contiki-ng supported devices. 