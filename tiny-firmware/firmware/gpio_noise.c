/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include <libopencm3/stm32/gpio.h>
#include "gpio_noise.h"

uint16_t read_gpio_noise(uint8_t port, uint8_t pin) {

  uint32_t ports[] = { 0, GPIOA, GPIOB, GPIOC, GPIOD, GPIOE, GPIOF, GPIOG, GPIOH, GPIOI };
  uint32_t pins[] = { 0, GPIO1, GPIO2, GPIO3, GPIO4, GPIO5, GPIO6, GPIO7, GPIO8 };

  uint32_t currentPin;
  uint32_t currentPort;

  static uint16_t salt = 0;
  static uint8_t shift = 3;

  ++salt;
  shift = ((shift + 1) & 0x3) + 4;

  if ( 1 <= pin && pin <= 8 ) {
    currentPin = pins[pin];
  } else {
    currentPin = GPIO_ALL;
  }

  if ( 1 <= port && port <= 9 ) {
    currentPort = ports[port];
  } else {
    currentPort = (GPIOC);
  }

  gpio_mode_setup(currentPort, GPIO_MODE_INPUT, GPIO_PUPD_NONE, currentPin);

  uint16_t ret = gpio_port_read(currentPort);

  return ret ^ ( ret << shift ) ^ salt;

}