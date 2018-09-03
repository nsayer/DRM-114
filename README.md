# DRM-114

This is the firmware for [DRM-114](https://hackaday.io/project/160434-drm-114).

DRM-114 is a #badgelife add-on for DEFCON 2018. It uses a new 6 pin variant of the SAO connector with the extra two pins being TTL
async serial receive and transmit. The host badge is intended to provide a dumb terminal. The functionality of DRM-114 is to provide
a secure optical chat and private messaging system. The security of this system relies on the fact that one file of the firmware
is proprietary and *not* open-source. That one file represents an "effective means of access control" for the purposes of section
1201 of the DMCA, and any attempts to reverse-engineer it are thus a violation of US federal law.

The hardware is an ATXmega32E5, an IR emitter (LED) and a 36 kHz IR receiver/demodulator. The controller will modulate the IR transmit
data with a 36 kHz optical carrier and the receiver will demodulate received signals for us.

The firmware is designed to have an interface similar to IRC. Any line typed is sent to the currently designated destination (either
a specific nickname or to evreryone). Commands are lines that start with a "/" and are used to set the local nickname, to change the
current message destination, request attention (there is a visible LED that the firmware can blink) or repeat the last IR frame.

The firmware is covered by GPL v2, with the exception of the AES module (which is covered by the same license as the Bouncycastle
library), and the key protection library, which is closed-source (the interface, however, is open, and anyone is allowed to provide
their own implementation, provided it does not interoperate with the closed-source variant).
