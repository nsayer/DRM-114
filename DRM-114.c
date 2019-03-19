
/*

    DRM-114
    Copyright (C) 2018-2019 Nicholas W. Sayer

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    
  */

#include <avr/cpufunc.h>
#include <avr/interrupt.h>
#include <avr/io.h>
#include <avr/wdt.h>
#include <avr/pgmspace.h>
#include <avr/eeprom.h>
#include <util/atomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "AES.h"
#include "crypto.h"

// V3 hardware moves the ATTN pin to D7 to get out of the way of the i2c
// pins.
//#define V3

// Serial baud constants for 115200 bps @ 32 MHz
#define BSEL115 (131)
#define BSCALE115 (-3)
// Serial baud constants for 4800 bps @ 32 MHz
#define BSEL48 (12)
#define BSCALE48 (5)

#define MAX_IR_FRAME (192)
volatile uint8_t ir_rx_buf[MAX_IR_FRAME];
volatile uint8_t ir_tx_buf[MAX_IR_FRAME];
volatile uint16_t ir_rx_ptr;
volatile uint16_t ir_tx_head, ir_tx_tail;

#define USER_BUF_SIZE (128)
volatile uint8_t user_rx_buf[USER_BUF_SIZE];
volatile uint8_t user_tx_buf[USER_BUF_SIZE];
volatile uint16_t user_tx_head, user_tx_tail;
volatile uint16_t user_rx_head, user_rx_tail;

volatile uint8_t ir_frame_good;

// This is a millisecond counter, used for blinking the attention LED.
volatile uint32_t ticks;

uint32_t blink_start;

#define MAX_NAME_SIZE (16)
char myname[MAX_NAME_SIZE];
char talkname[MAX_NAME_SIZE];

#define MAX_INPUT_LINE (80)
char input_line[MAX_INPUT_LINE];
uint16_t input_line_pos;

uint8_t last_ir_frame[MAX_IR_FRAME];
size_t last_ir_frame_len;

// The types of messages allowed.
// Broadcast text
#define MSG_BROADCAST (0)
// Directed text
#define MSG_DIRECTED (1)
// Broadcast attention
#define MSG_ATT_BROADCAST (2)
// Directed attention
#define MSG_ATT_DIRECTED (3)

// Special characters
#define STX (2)
#define ETX (3)
#define BEL (7)
#define BS (8)
#define NL (10)
#define CR (13)
#define DLE (16)
#define DEL (127)

// This keeps the millisecond counter
ISR(TCC4_OVF_vect) {
	TCC4.INTFLAGS = TC4_OVFIF_bm; // ACK
	ticks++;
}

// TX complete for IR. Turn the IR receiver back on
ISR(USARTD0_TXC_vect) {
	USARTD0.CTRLB |= USART_RXEN_bm; // turn the receiver back on
}

// TX data empty for user port. This is a simple interrupt driven transmit buffer.
ISR(USARTC0_DRE_vect) {
	if (user_tx_head == user_tx_tail) {
		// the transmit queue is empty.
		USARTC0.CTRLA &= ~USART_DREINTLVL_gm; // disable the TX interrupt.
		//USARTC0.CTRLA |= USART_DREINTLVL_OFF_gc; // redundant - off is a zero value
		return;
	}
	USARTC0.DATA = user_tx_buf[user_tx_tail];
	if (++user_tx_tail == sizeof(user_tx_buf)) user_tx_tail = 0; // point to the next char
}

// RX complete for the user port. Just gather characters into the input buffer.
ISR(USARTC0_RXC_vect) {
	uint8_t c = USARTC0.DATA;
	int buf_in_use = user_rx_head - user_rx_tail;
	if (buf_in_use < 0) buf_in_use += sizeof(user_rx_buf);
	if (buf_in_use >= sizeof(user_rx_buf) - 2) return; // buffer is full, throw it away
	user_rx_buf[user_rx_head] = c;
	if (++user_rx_head == sizeof(user_rx_buf)) user_rx_head = 0; // point to the next free spot in the rx buffer
}

// TX data empty for IR. This is also just a simple interrupt driven transmit buffer.
ISR(USARTD0_DRE_vect) {
	if (ir_tx_head == ir_tx_tail) {
		// the transmit queue is empty.
		USARTD0.CTRLA &= ~USART_DREINTLVL_gm; // disable the TX interrupt.
		//USARTD0.CTRLA |= USART_DREINTLVL_OFF_gc; // redundant - off is a zero value
		return;
	}
	USARTD0.DATA = ir_tx_buf[ir_tx_tail];
	if (++ir_tx_tail == sizeof(ir_tx_buf)) ir_tx_tail = 0; // point to the next char
}

// RX complete for the IR port. Use the DLE protocol to gather frames, then mark them as good.
ISR(USARTD0_RXC_vect) {
	static uint8_t in_dle = 0;
	static uint8_t rx_en = 0;

	uint8_t c = USARTD0.DATA;
	if (in_dle) {
		in_dle = 0;
		switch(c) {
			case STX:
				ir_rx_ptr = 0; // start the frame
				rx_en = 1; // enable reception
				break;
			case ETX:
				ir_frame_good = 1; // tell the higher level a frame is ready
				rx_en = 0;
				break;
			case DLE:
				goto rx_dle;
			// default fall through
		}
		return;
	}
	if (c == DLE) {
		in_dle = 1;
		return;
	}
rx_dle:
	if (!rx_en) return; // we're not receiving
	ir_rx_buf[ir_rx_ptr++] = c;
	if (ir_rx_ptr >= sizeof(ir_rx_buf)) {
		// frame too long.
		ir_rx_ptr = 0;
		rx_en = 0;
	}
}

static uint16_t user_rx_char() {
	uint16_t out;
	ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
		if (user_rx_head == user_rx_tail)
			out = 0xffff;
		else {
			out = user_rx_buf[user_rx_tail];
			if (++user_rx_tail == sizeof(user_rx_buf)) user_rx_tail = 0;
		}
	}
	return out;
}

static inline void ir_tx_char(uint8_t c) {
	int buf_in_use;
	do {
		ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
			buf_in_use = ir_tx_head - ir_tx_tail;
		}
		if (buf_in_use < 0) buf_in_use += sizeof(ir_tx_buf);
		wdt_reset(); // we might be waiting a while.
	} while (buf_in_use >= sizeof(ir_tx_buf) - 2) ; // wait for room in the transmit buffer

	ir_tx_buf[ir_tx_head] = c;
	ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
		// this needs to be atomic, because an intermediate state is tx_buf_head
		// pointing *beyond* the end of the buffer.
		if (++ir_tx_head == sizeof(ir_tx_buf)) ir_tx_head = 0; // point to the next free spot in the tx buffer
	}
	//USARTD0.CTRLA &= ~USART_DREINTLVL_gm; // this is redundant - it was already 0
	USARTD0.CTRLB &= ~USART_RXEN_bm; // turn the receiver off while we're transmitting.
	USARTD0.CTRLA |= USART_DREINTLVL_HI_gc; // enable the TX interrupt. If it was disabled, then it will trigger one now.
}

static inline void user_tx_char(uint8_t c) {
	int buf_in_use;
	do {
		ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
			buf_in_use = user_tx_head - user_tx_tail;
		}
		if (buf_in_use < 0) buf_in_use += sizeof(user_tx_buf);
		wdt_reset(); // we might be waiting a while.
	} while (buf_in_use >= sizeof(user_tx_buf) - 2) ; // wait for room in the transmit buffer

	user_tx_buf[user_tx_head] = c;
	ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
		// this needs to be atomic, because an intermediate state is tx_buf_head
		// pointing *beyond* the end of the buffer.
		if (++user_tx_head == sizeof(user_tx_buf)) user_tx_head = 0; // point to the next free spot in the tx buffer
	}
	//USARTC0.CTRLA &= ~USART_DREINTLVL_gm; // this is redundant - it was already 0
	USARTC0.CTRLA |= USART_DREINTLVL_MED_gc; // enable the TX interrupt. If it was disabled, then it will trigger one now.
}

static void print_pstring(const char * msg) {
	for(int i = 0; i < strlen_P(msg); i++) {
		user_tx_char(pgm_read_byte(&msg[i]));
	}
}

//#define DEBUG 1
const char hexes[] PROGMEM = "0123456789abcdef";

// Queue up an IR frame for transmission
static void ir_tx_frame(uint8_t *buf, size_t len) {
#ifdef DEBUG
	print_pstring(PSTR("TX: "));
	for(int j = 0; j < len; j++) {
		user_tx_char(pgm_read_byte(&(hexes[buf[j] >> 4])));
		user_tx_char(pgm_read_byte(&(hexes[buf[j] & 0xf])));
	}
	print_pstring(PSTR("\r\n\r\n"));
#endif
	ir_tx_char(DLE);
	ir_tx_char(STX);
	for(int i = 0; i < len; i++) {
		if (buf[i] == DLE) ir_tx_char(DLE);
		ir_tx_char(buf[i]);
	}
	ir_tx_char(DLE);
	ir_tx_char(ETX);
}

static void print_string(const char *str) {
	for(int i = 0; i < strlen(str); i++)
		user_tx_char(str[i]);
}

static void print_prompt() {
	print_string(talkname);
	user_tx_char('>');
	user_tx_char(' ');
}

static void print_achtung(uint8_t *buf) {
	ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
		blink_start = ticks;
		if (blink_start == 0) blink_start++; // it's not allowed to be set to zero
	}
	user_tx_char(CR); // no NL - we will over-print the input buffer
	user_tx_char(BEL); // BEL
	print_string((char *)buf); // the sender's name
	print_pstring(PSTR(" wants attention."));
	int remaining = input_line_pos - (strlen((char *)buf) + 17);
	for(int i = 0; i < remaining + 2; i++) user_tx_char(' '); // overwrite the input line
	user_tx_char(CR);
	user_tx_char(NL);
	print_prompt();
	for(int i = 0; i < input_line_pos; i++) user_tx_char(input_line[i]); // reprint the user's input line
}

static void print_message(uint8_t *buf) {
	user_tx_char(CR); // no NL - we will over-print the input buffer
	print_string((char *)buf); // the sender's name
	user_tx_char(':');
	user_tx_char(' ');
	print_string((char *)buf + strlen((char *)buf) + 1);
	int remaining = input_line_pos - (strlen((char *)buf) + strlen((char *)buf + strlen((char *)buf) + 1) + 2);
	for(int i = 0; i < remaining + 2; i++) user_tx_char(' '); // overwrite the input line
	user_tx_char(CR);
	user_tx_char(NL);
	print_prompt();
	for(int i = 0; i < input_line_pos; i++) user_tx_char(input_line[i]); // reprint the user's input line
}

static void handle_ir_frame(uint8_t *buf, size_t len) {
	uint8_t pt_msg[MAX_IR_FRAME];
	size_t pt_size = MAX_IR_FRAME;
	size_t pos;
	if (!decrypt_message(buf, len, pt_msg, &pt_size)) return; // bad decrypt - ignore
	if (pt_size == 0) return; // empty message
	switch(pt_msg[0]) {
		case MSG_BROADCAST: // broadcast message
			// After the type byte, there's a null-terminated source identity.
			// after that is the null-terminated message.
			pt_msg[len] = 0; // null terminate
			print_message(pt_msg + 1);
			break;
		case MSG_DIRECTED: // directed message
			// After the type byte, there's a null-terminated dest identity.
			// after that, there is the null-terminated source identity.
			// after that is the null-terminated message.
			if (strcasecmp((const char *)myname, (const char *)pt_msg + 1)) return; // not for me
			pos = strlen((const char *)pt_msg + 1) + 2; // +1 for the null, +1 for the type byte
			pt_msg[len] = 0; // null terminate
			print_message(pt_msg + pos);
			break;
		case MSG_ATT_BROADCAST: // broadcast attention
			// After the type byte, there's a null-terminated source idenity.
			print_achtung(pt_msg + 1);
			break;
		case MSG_ATT_DIRECTED: // directed attention
			// After the type byte, there's a null-terminated dest idenity.
			// after that, there is the null-terminated source identity.
			if (strcasecmp((const char *)myname, (const char *)pt_msg + 1)) return; // not for me
			pos = strlen((const char *)pt_msg + 1) + 2; // +1 for the null, +1 for the type byte
			pt_msg[len] = 0; // null terminate
			print_achtung(pt_msg + pos);
			break;
	}
			
}

static void print_help() {
	print_pstring(PSTR("Help:\r\n"));
	print_pstring(PSTR(" /n [name]     Sets your name.\r\n"));
	print_pstring(PSTR(" /t [name]     Sets the name of your talk partner. Omit name for broadcasts.\r\n"));
	print_pstring(PSTR(" /r            Repeats the last transmission.\r\n"));
	print_pstring(PSTR(" /a            Requests attention (from everyone or current talk partner).\r\n"));
	print_pstring(PSTR(" /h or /?      Prints this help.\r\n"));
	print_pstring(PSTR(" Any other line of text is transmitted to either everyone or your talk partner.\r\n"));
}

static const char *getarg(const char *input_line) {
	// skip to the first space, then skip past spaces.
	int count;
	for(count = 0; input_line[count] != ' '; count++)
		if (input_line[count] == 0) return NULL; // ran off the end
	for(; input_line[count] == ' '; count++)
		if (input_line[count] == 0) return NULL; // ran off the end
	return input_line + count;
}

static void save_username() {
	eeprom_write_byte((uint8_t*)0, strlen(myname));
	for(int i = 0; i < strlen(myname); i++)
		eeprom_write_byte((uint8_t*)(i + 1), myname[i]);
}

static void load_username() {
	size_t len =  eeprom_read_byte((uint8_t*)0);
	if (len > MAX_NAME_SIZE) return; // no change
	for(int i = 0; i < len; i++)
		myname[i] = eeprom_read_byte((uint8_t*)(i + 1));
	myname[len] = 0;
}

static void handle_line() {
	uint8_t pt_buf[MAX_IR_FRAME];
	size_t pos;
	if (strlen(input_line) == 0) return;
	if (input_line[0] == '/') {
		const char *arg = getarg(input_line);
		switch(input_line[1]) {
			case 'h':
			case 'H':
			case '?':
				print_help();
				return;
			case 'n':
			case 'N':
				if (arg != NULL) {
					if (strlen(arg) > MAX_NAME_SIZE - 1) {
						print_pstring(PSTR("Name too long.\r\n"));
						return;
					}
					strcpy(myname, arg);
					save_username();
					print_pstring(PSTR("Your name is now "));
					print_string(myname);
					print_pstring(PSTR(".\r\n"));
					return;
				}
				print_pstring(PSTR("Your name is "));
				print_string(myname);
				print_pstring(PSTR(".\r\n"));
				return;
			case 't':
			case 'T':
				if (arg == NULL) {
					talkname[0] = 0; // remove it
					print_pstring(PSTR("Broadcasting.\r\n"));
				} else {
					if (strlen(arg) > MAX_NAME_SIZE - 1) {
						print_pstring(PSTR("Name too long.\r\n"));
						return;
					}
					strcpy(talkname, arg);
					print_pstring(PSTR("Talking to "));
					print_string(talkname);
					print_pstring(PSTR(".\r\n"));
				}
				return;
			case 'r':
			case 'R':
				if (last_ir_frame_len == 0) {
					print_pstring(PSTR("There is nothing to repeat.\r\n"));
					return;
				}
				ir_tx_frame(last_ir_frame, last_ir_frame_len);
				return;
			case 'a':
			case 'A':
				if (strlen(talkname) == 0) {
					// broadcast
					pt_buf[0] = MSG_ATT_BROADCAST;
					strcpy((char *)pt_buf + 1, myname);
					pos = strlen(myname) + 2;
				} else {
					pt_buf[0] = MSG_ATT_DIRECTED;
					strcpy((char *)pt_buf + 1, talkname);
					strcpy((char *)pt_buf + strlen(talkname) + 2, myname);
					pos = strlen(myname) + strlen(talkname) + 3;
					// directed
				}
				last_ir_frame_len = sizeof(last_ir_frame);
				if (!encrypt_message(pt_buf, pos, last_ir_frame, &last_ir_frame_len)) {
					print_pstring(PSTR("Encrypt error (should never happen).\r\n"));
					return;
				}
				ir_tx_frame(last_ir_frame, last_ir_frame_len);
				print_pstring(PSTR("Sent attention!\r\n"));
				return;
			default:
				print_pstring(PSTR("Invalid command. /? for help.\r\n"));
				return;
		}
	}
	// create new message
	if (strlen(talkname) > 0) {
		pt_buf[0] = MSG_DIRECTED;
		strcpy((char*)pt_buf + 1, talkname);
		pos = strlen(talkname) + 2; // the null and the type byte
	} else {
		pt_buf[0] = MSG_BROADCAST;
		pos = 1;
	}
	strcpy((char *)pt_buf + pos, myname);
	strcpy((char *)pt_buf + pos + strlen(myname) + 1, input_line);
	last_ir_frame_len = sizeof(last_ir_frame);
	if (!encrypt_message(pt_buf, pos + strlen(myname) + strlen(input_line) + 2, last_ir_frame, &last_ir_frame_len)) {
		print_pstring(PSTR("Encrypt error (should never happen).\r\n"));
		return;
	}
	ir_tx_frame(last_ir_frame, last_ir_frame_len);
}

void __ATTR_NORETURN__ main(void) {

	// We have a 16 MHz crystal. Use the PLL to double that to 32 MHz.

	OSC.XOSCCTRL = OSC_FRQRANGE_12TO16_gc | OSC_XOSCSEL_XTAL_16KCLK_gc;
	OSC.CTRL |= OSC_XOSCEN_bm;
	while(!(OSC.STATUS & OSC_XOSCRDY_bm)) ; // wait for it.

	OSC.PLLCTRL = OSC_PLLSRC_XOSC_gc | (2 << OSC_PLLFAC_gp); // PLL from XOSC, mult by 2
	OSC.CTRL |= OSC_PLLEN_bm;
	while(!(OSC.STATUS & OSC_PLLRDY_bm)) ; // wait for it.

	_PROTECTED_WRITE(CLK.CTRL, CLK_SCLKSEL_PLL_gc); // switch to it
	OSC.CTRL &= ~(OSC_RC2MEN_bm); // we're done with the 2 MHz osc.

	// Configure the watchdog

	_PROTECTED_WRITE(WDT.CTRL, WDT_PER_256CLK_gc | WDT_ENABLE_bm | WDT_CEN_bm); // 1/4 second
	while(WDT.STATUS & WDT_SYNCBUSY_bm) ; // wait for it to take
	// We don't want a windowed watchdog.
	_PROTECTED_WRITE(WDT.WINCTRL, WDT_WCEN_bm);
	while(WDT.STATUS & WDT_SYNCBUSY_bm) ; // wait for it to take

	// Leave on only the parts of the chip we actually use
	// So the XCL, timer C4 and the two USARTs.
	PR.PRGEN = PR_RTC_bm | PR_EVSYS_bm | PR_EDMA_bm;
	PR.PRPA = PR_DAC_bm | PR_ADC_bm | PR_AC_bm;
#ifdef V3
	PR.PRPC = PR_SPI_bm | PR_HIRES_bm | PR_TC5_bm;
#else
	PR.PRPC = PR_TWI_bm | PR_SPI_bm | PR_HIRES_bm | PR_TC5_bm;
#endif
	PR.PRPD = PR_TC5_bm;

	PORTC.OUTCLR = _BV(0); // the LED starts off
	PORTC.OUTSET = _BV(3); // TXD defaults to high, but we really don't use it anyway
#ifdef V3
	PORTC.DIRSET = _BV(3); // TXD is an output
#else
	PORTC.DIRSET = _BV(0) | _BV(3); // ATTN and TXD is an output.
#endif

	PORTD.PIN3CTRL = PORT_INVEN_bm; // invert the TX pin.
	PORTD.OUTSET = _BV(3); // TXD defaults to high, but we really don't use it anyway
#ifdef V3
	PORTD.DIRSET = _BV(3) | _BV(7); // ATTN and TXD is an output.
#else
	PORTD.DIRSET = _BV(3); // TXD is an output.
#endif

	// TCC4 is a millisecond counter
	TCC4.CTRLA = TC45_CLKSEL_DIV256_gc; // 125 kHz timer clocking
	TCC4.CTRLB = 0;
	TCC4.CTRLC = 0;
	TCC4.CTRLD = 0;
	TCC4.CTRLE = 0;
	TCC4.INTCTRLA = TC45_OVFINTLVL_LO_gc;
	TCC4.INTCTRLB = 0;
	TCC4.PER = 124; // 125 - 1

	// XCL's job is to modulate the transmit data with a 36 kHz optical carrier.
	XCL.CTRLA = XCL_PORTSEL_PD_gc; // port D, 2 independent LUT, no LUT out pins
	XCL.CTRLB = XCL_IN3SEL0_bm | XCL_IN2SEL0_bm; // LUT 1 inputs from XCL
	XCL.CTRLC = 0; // no delays
	XCL.CTRLD = 0b11100000; // clock output when serial is 0, no out when serial is 1, but all inverse.
	XCL.CTRLE = XCL_TCSEL_BTC0_gc | XCL_CLKSEL_DIV8_gc; // one 8 bit counter with period, divide by 8 clock.
	XCL.CTRLF = XCL_TCMODE_PWM_gc; // PWM counter mode
	XCL.CTRLG = 0; // no event action
	XCL.INTCTRL = 0; // no interrupts
	XCL.PERCAPTL = 110; // 36 kHz
	XCL.CMPL = 110/2; // 50% (ish) duty cycle

	// 115200 baud async serial, 8N1, med priority interrupt on receive
	USARTC0.CTRLA = USART_DRIE_bm | USART_RXCINTLVL_MED_gc;
	USARTC0.CTRLB = USART_RXEN_bm | USART_TXEN_bm;
	USARTC0.CTRLC = USART_CHSIZE_8BIT_gc;
	USARTC0.CTRLD = 0;
	USARTC0.BAUDCTRLA = BSEL115 & 0xff;
	USARTC0.BAUDCTRLB = (BSEL115 >> 8) | (BSCALE115 << USART_BSCALE_gp);

	// 4800 baud async serial, 8N1, hi priority interrupt on receive and TX complete, XCL on TX
	USARTD0.CTRLA = USART_DRIE_bm | USART_RXCINTLVL_HI_gc | USART_TXCINTLVL_LO_gc;
	USARTD0.CTRLB = USART_RXEN_bm | USART_TXEN_bm;
	USARTD0.CTRLC = USART_CHSIZE_8BIT_gc;
	USARTD0.CTRLD = USART_DECTYPE_SDATA_gc | USART_LUTACT_TX_gc;
	USARTD0.BAUDCTRLA = BSEL48 & 0xff;
	USARTD0.BAUDCTRLB = (BSEL48 >> 8) | (BSCALE48 << USART_BSCALE_gp);

#ifdef V3
	// to-do: set up i2c... for what?
#endif

	ir_rx_ptr = 0;
	ir_frame_good = 0;
	ir_tx_head = ir_tx_tail = 0;
	last_ir_frame_len = 0;
	blink_start = 0;

	user_tx_head = user_tx_tail = 0;
	user_rx_head = user_rx_tail = 0;

	talkname[0] = 0; // start broadcasting
	input_line_pos = 0;

	// Read in serial number to initialize PRNG seed
	{
		unsigned char serial[11];
		NVM.CMD = NVM_CMD_READ_CALIB_ROW_gc;
		serial[0] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, LOTNUM0));
		serial[1] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, LOTNUM1));
		serial[2] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, LOTNUM2));
		serial[3] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, LOTNUM3));
		serial[4] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, LOTNUM4));
		serial[5] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, LOTNUM5));
		serial[6] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, WAFNUM));
		serial[7] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, COORDX1));
		serial[8] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, COORDX0));
		serial[9] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, COORDY1));
		serial[10] = pgm_read_byte(offsetof(NVM_PROD_SIGNATURES_t, COORDY0));
		NVM.CMD = NVM_CMD_NO_OPERATION_gc;
		PRNG_init(serial, sizeof(serial));
	}
	*myname = 0;
	load_username();
	if (*myname == 0) {
		uint8_t rand_name[2];
		PRNG(rand_name, sizeof(rand_name));
		strcpy_P(myname, PSTR("def_XXXX"));
		myname[4] = pgm_read_byte(&hexes[rand_name[0] >> 4]);
		myname[5] = pgm_read_byte(&hexes[rand_name[0] & 0xf]);
		myname[6] = pgm_read_byte(&hexes[rand_name[1] >> 4]);
		myname[7] = pgm_read_byte(&hexes[rand_name[1] & 0xf]);
		save_username();
	}

	PMIC.CTRL = PMIC_HILVLEN_bm | PMIC_MEDLVLEN_bm | PMIC_LOLVLEN_bm;
	sei();

	// Print startup message
	print_pstring(PSTR("\r\n\r\nDRM-114\r\n"));
	print_pstring(PSTR("Copyright 2018-2019 Nick Sayer\r\n"));
	print_pstring(PSTR("/? for help\r\n"));
	print_prompt();

	while(1) {
		// Main loop tasks...
		// 1. Pet the watchdog
		wdt_reset();

		// 2. Handle incoming IR frames
		if (ir_frame_good) {
			// first, save the frame in case another comes in.
			uint8_t buf[MAX_IR_FRAME];
			size_t len;
			ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
				len = ir_rx_ptr;
				memcpy(buf, (const uint8_t *)ir_rx_buf, len);
				ir_frame_good = 0; // ACK
			}
#if DEBUG
			print_pstring(PSTR("RX: "));
			for(int j = 0; j < len; j++) {
				user_tx_char(pgm_read_byte(&(hexes[buf[j] >> 4])));
				user_tx_char(pgm_read_byte(&(hexes[buf[j] & 0xf])));
			}
			print_pstring(PSTR("\r\n\r\n"));
#endif
			handle_ir_frame(buf, len);
			continue;
		}

		// 3. Handle incoming user chars
		uint16_t c;
		if ((c = user_rx_char()) != 0xffff) {
			c &= 0x7f;
			switch(c) {
				case BS:
				case DEL:
					if (input_line_pos == 0) continue; // can't backspace past beinning
					input_line_pos--;
					user_tx_char(BS);
					user_tx_char(' ');
					user_tx_char(BS);
					continue;
				case NL:
				case CR:
					user_tx_char(CR);
					user_tx_char(NL);
					input_line[input_line_pos] = 0; // null terminate
					handle_line();
					print_prompt();
					input_line_pos = 0;
					continue;
			}
			if (c < 32) continue; // ignore all other control chars
			if (input_line_pos >= sizeof(input_line)) {
				user_tx_char(BEL);
				continue;
			}
			input_line[input_line_pos++] = (char)c;
			user_tx_char((uint8_t)c);
			continue;
		}
		// 4. Handle LED blinking
		if (blink_start != 0) {
			uint32_t blink_pos;
			ATOMIC_BLOCK(ATOMIC_RESTORESTATE) {
				blink_pos = ticks - blink_start;
			}
			blink_pos /= 100; // the blink timing is 1/10 sec blinks for 1/2 sec.
			if (blink_pos >= 6) {
#ifdef V3
				PORTD.OUTCLR = _BV(7); // turn it off
#else
				PORTC.OUTCLR = _BV(0); // turn it off
#endif
				blink_start = 0; // we're done
				continue;
			}
			if (blink_pos % 2)
#ifdef V3
				PORTD.OUTCLR = _BV(7);
#else
				PORTC.OUTCLR = _BV(0);
#endif
			else
#ifdef V3
				PORTD.OUTSET = _BV(7);
#else
				PORTC.OUTSET = _BV(0);
#endif
		}
	}
}
