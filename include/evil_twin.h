#ifndef EVIL_TWIN_H
#define EVIL_TWIN_H

#include <Arduino.h>

void start_evil_twin(int wifi_number);
void stop_evil_twin();
void evil_twin_loop();
bool evil_twin_test_password(const String &password);

extern bool   evil_twin_active;
extern String evil_twin_ssid;
extern int    evil_twin_clients;
extern int    evil_twin_channel;
extern uint8_t evil_twin_bssid[6];

#endif
