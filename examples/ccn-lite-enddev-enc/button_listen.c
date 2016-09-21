/*
 * button_listen.c
 *
 *  Created on: Sep 16, 2016
 *      Author: joakim
 */
#include "periph/gpio.h"
#include "thread.h"
#include "board.h"
#include "abe_relic.h"
#include "xtimer.h"

/*!
 * Checks whether the user button on the stm32f4-discovery board is pressed.
 * (need "periph/gpio.h" included).
 *
 * @note 		Need to call gpio_init(GPIO_PIN(PORT_A, 0), GPIO_IN), before
 * 				first usage
 *
 * @return		Returns 1 if pressed, 0 otherwise
 */
int read_button(void){
	if (gpio_read(GPIO_PIN(PORT_A, 0)) != 0)
		return 1;
	return 0;
}

/*!
 * Sets the LEDs based on the state, according to:
 * 		state		LED on
 * 		  0			green (LED1)
 * 		  1			red	  (LED2)
 */
void set_LED_from_state(int state){
	switch (state) {
		case 0:
			LED2_OFF;
			LED1_ON;
			break;
		case 1:
			LED1_OFF;
			LED2_ON;
	}

}

void* button_listen_thread(void *args){
	gpio_init(GPIO_PIN(PORT_A,0), GPIO_IN);

	set_LED_from_state(get_state());
	while (1){
		if (read_button() == 1){
			change_state();
			set_LED_from_state(get_state());

			xtimer_usleep(50000);
		}
		thread_yield();
	}

	return NULL;
}
