
/*

    DRM-114
    Copyright (C) 2018 Nicholas W. Sayer

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
#include <util/atomic.h>
#include <stdlib.h>
#include <string.h>
#include "AES.h"
#include "crypto.h"

// Serial baud constants for 9600 bps @ 32 MHz
#define BSEL96 (12)
#define BSCALE96 (4)
// Serial baud constants for 4800 bps @ 32 MHz
#define BSEL48 (12)
#define BSCALE48 (5)

// A start of frame is DLE+STX. An end-of-frame is DLE+ETX. Any organic DLE char is repeated.
#define DLE (0x70)
#define STX (0x71)
#define ETX (0x72)

#define MAX_IR_FRAME (128)
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

#define MAX_NAME_SIZE (16)
char *myname[MAX_NAME_SIZE];

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

// For the user port, just gather characters into the input buffer.
ISR(USARTC0_RXC_vect) {
	uint8_t c = USARTC0.DATA;
	int buf_in_use = user_rx_head - user_rx_tail;
	if (buf_in_use < 0) buf_in_use += sizeof(user_rx_buf);
	if (buf_in_use >= sizeof(user_rx_buf) - 2) return; // buffer is full, throw it away
	user_rx_buf[user_rx_head] = c;
	if (++user_rx_head == sizeof(user_rx_buf)) user_rx_head = 0; // point to the next free spot in the rx buffer
}

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

// For the IR port, use the DLE protocol to gather frames, then mark them as good.
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
		if (user_rx_head == user_tx_head)
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
        USARTD0.CTRLA |= USART_DREINTLVL_LO_gc; // enable the TX interrupt. If it was disabled, then it will trigger one now.
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
        USARTC0.CTRLA |= USART_DREINTLVL_LO_gc; // enable the TX interrupt. If it was disabled, then it will trigger one now.
}

// Queue up an IR frame for transmission
static void ir_tx_frame(uint8_t *buf, size_t len) {
	ir_tx_char(DLE);
	ir_tx_char(STX);
	for(int i = 0; i < len; i++) {
		if (buf[i] == DLE) ir_tx_char(DLE);
		ir_tx_char(buf[i]);
	}
	ir_tx_char(DLE);
	ir_tx_char(ETX);
}

static void print_message(uint8_t *buf);
static void handle_ir_frame(uint8_t *buf, size_t len) {
	uint8_t pt_msg[MAX_IR_FRAME];
	size_t pt_size = MAX_IR_FRAME;
	if (!decrypt_message(buf, len, pt_msg, &pt_size)) return; // bad decrypt - ignore
	if (pt_size == 0) return; // empty message
	switch(pt_msg[0]) {
		case 0: // broadcast message
			// After the type byte, there's a null-terminated source identity.
			// after that is the null-terminated message.
			pt_msg[len] = 0; // null terminate
			print_message(pt_msg + 1);
			break;
		case 1: // directed message
			// After the type byte, there's a null-terminated dest identity.
			// after that, there is the null-terminated source identity.
			// after that is the null-terminated message.
			if (strcasecmp((const char *)myname, (const char *)pt_msg + 1)) return; // not for me
			unsigned int pos = strlen((const char *)pt_msg + 1) + 2; // +1 for the null, +1 for the type byte
			pt_msg[len] = 0; // null terminate
			print_message(pt_msg + pos);
			break;
	}
			
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

#if 0
        _PROTECTED_WRITE(WDT.CTRL, WDT_PER_256CLK_gc | WDT_ENABLE_bm | WDT_CEN_bm);
        while(WDT.STATUS & WDT_SYNCBUSY_bm) ; // wait for it to take
        // We don't want a windowed watchdog.
        _PROTECTED_WRITE(WDT.WINCTRL, WDT_WCEN_bm);
        while(WDT.STATUS & WDT_SYNCBUSY_bm) ; // wait for it to take
#endif

	// Leave on only the parts of the chip we actually use
	// So the XCL and the two USARTs.
	PR.PRGEN = PR_RTC_bm | PR_EVSYS_bm | PR_EDMA_bm;
	PR.PRPA = PR_DAC_bm | PR_ADC_bm | PR_AC_bm;
	PR.PRPC = PR_TWI_bm | PR_SPI_bm | PR_HIRES_bm | PR_TC5_bm | PR_TC4_bm;
	PR.PRPD = PR_TC5_bm;

	PORTC.OUTSET = _BV(3); // TXD defaults to high, but we really don't use it anyway
        PORTC.DIRSET = _BV(3); // TXD is an output.
	PORTD.PIN3CTRL = PORT_INVEN_bm; // invert the TX pin.
	PORTD.OUTSET = _BV(3); // TXD defaults to high, but we really don't use it anyway
        PORTD.DIRSET = _BV(3); // TXD is an output.

	XCL.CTRLA = XCL_PORTSEL_PD_gc; // port D, 2 independent LUT, no LUT out pins
	XCL.CTRLB = XCL_IN3SEL0_bm | XCL_IN2SEL0_bm; // LUT 1 inputs from XCL
	XCL.CTRLC = 0; // no delays
	XCL.CTRLD = 0b11100000; // clock output when serial is 0, no out when serial is 1, but all inverse.
	XCL.CTRLE = XCL_TCSEL_BTC0_gc | XCL_CLKSEL_DIV8_gc; // one 8 bit counter with period, divide by 8 clock.
	XCL.CTRLF = XCL_TCMODE_PWM_gc; // PWM counter mode
	XCL.CTRLG = 0; // no event action
	XCL.INTCTRL = 0; // no interrupts
	XCL.PERCAPTL = 111; // 36 kHz
	XCL.CMPL = 111/2; // 50% (ish) duty cycle

        // 9600 baud async serial, 8N1, low priority interrupt on receive
        USARTC0.CTRLA = USART_DRIE_bm | USART_RXCINTLVL_LO_gc;
        USARTC0.CTRLB = USART_RXEN_bm | USART_TXEN_bm;
        USARTC0.CTRLC = USART_CHSIZE_8BIT_gc;
        USARTC0.CTRLD = 0;
        USARTC0.BAUDCTRLA = BSEL96 & 0xff;
        USARTC0.BAUDCTRLB = (BSEL96 >> 8) | (BSCALE96 << USART_BSCALE_gp);

        // 4800 baud async serial, 8N1, low priority interrupt on receive, XCL on TX
        USARTD0.CTRLA = USART_DRIE_bm | USART_RXCINTLVL_LO_gc;
        USARTD0.CTRLB = USART_RXEN_bm | USART_TXEN_bm;
        USARTD0.CTRLC = USART_CHSIZE_8BIT_gc;
        USARTD0.CTRLD = USART_DECTYPE_SDATA_gc | USART_LUTACT_TX_gc;
        USARTD0.BAUDCTRLA = BSEL48 & 0xff;
        USARTD0.BAUDCTRLB = (BSEL48 >> 8) | (BSCALE48 << USART_BSCALE_gp);

	ir_rx_ptr = 0;
	ir_frame_good = 0;
	ir_tx_head = ir_tx_tail = 0;

	user_tx_head = user_tx_tail = 0;
	user_rx_head = user_rx_tail = 0;

	myname[0] = 0; // start empty

	// XXX Read in serial number to initialize PRNG seed

	PMIC.CTRL = PMIC_HILVLEN_bm | PMIC_MEDLVLEN_bm | PMIC_LOLVLEN_bm;
	sei();

	// XXX Print startup message

	while(1) {
		// temporary test code - send every input user character out to IR.
		uint16_t c;
		while((c = user_rx_char()) == 0xffff);
		user_tx_char((uint8_t)c);
		ir_tx_char((uint8_t)c);
	}
}
