package com.example;

import java.awt.Desktop;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpServer;

import okhttp3.Credentials;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class OktaOrgDemo {

  static final String DOMAIN        = "https://integrator-4310404.okta.com";
  static final String CLIENT_ID     = "0oauwy143vqZWdw3c697";
  static final String CLIENT_SECRET = "d0cefwx5j_gExseX-G9leNFdAbH0GqYfwbE6BSN_fgkZDpIAbAmut2Jk1DmLb5sC"; // <- put new/rotated secret here
  static final String REDIRECT      = "http://localhost:8081/authorization-code/callback";
  static final String SCOPES        = "okta.orgs.read okta.users.read okta.logs.read";

  static final OkHttpClient HTTP = new OkHttpClient();

  static String AUTHZ() { return DOMAIN + "/oauth2/v1/authorize"; } 
  static String TOKEN() { return DOMAIN + "/oauth2/v1/token"; }

  static class Tokens { String access; String refresh; Instant exp; }
  static Tokens tok = new Tokens();

  public static void main(String[] args) throws Exception {
    if ("REPLACE_WITH_YOUR_NEW_SECRET".equals(CLIENT_SECRET)) {
      throw new IllegalStateException("Please paste your Okta client secret into CLIENT_SECRET.");
    }

   
    var server = HttpServer.create(new InetSocketAddress(8081), 0);
    final String state = UUID.randomUUID().toString();

    server.createContext("/authorization-code/callback", ex -> {
      Map<String, String> qs = parse(ex.getRequestURI().getQuery());
      String code = qs.get("code");
      String st   = qs.get("state");
      String msg;
      try {
        if (code != null && state.equals(st)) {
          exchangeCode(code);
          msg = "Auth complete. You can close this tab.";
        } else {
          msg = "Missing ?code or state mismatch.";
        }
      } catch (Exception e) {
        msg = "Token exchange failed: " + e.getMessage();
      }
      byte[] b = msg.getBytes(StandardCharsets.UTF_8);
      ex.sendResponseHeaders(200, b.length);
      try (var os = ex.getResponseBody()) { os.write(b); }
      ex.close();
    });
    server.start();

    String url = AUTHZ()
      + "?response_type=code"
      + "&client_id="    + enc(CLIENT_ID)
      + "&redirect_uri=" + enc(REDIRECT)
      + "&scope="        + enc(SCOPES)   
      + "&state="        + enc(state);

    open(url);
    System.out.println("Authorize in the browser…");

    while (tok.access == null) Thread.sleep(250);

    Request req = new Request.Builder()
      .url(DOMAIN + "/api/v1/org")
      .addHeader("Authorization", "Bearer " + ensureAccess())
      .build();

    try (Response r = HTTP.newCall(req).execute()) {
      if (!r.isSuccessful()) throw new IOException("HTTP " + r.code() + ": " + r.body().string());
      String body = r.body().string();
      System.out.println("=== /api/v1/org ===\n" + body);

      JsonObject o = JsonParser.parseString(body).getAsJsonObject();
      if (o.has("companyName")) {
        System.out.println("Org companyName: " + o.get("companyName").getAsString());
      }
    }

    server.stop(0);
  }


  static void exchangeCode(String code) throws IOException {
    RequestBody form = new FormBody.Builder()
      .add("grant_type", "authorization_code")
      .add("code", code)
      .add("redirect_uri", REDIRECT)
      .build();

    Request req = new Request.Builder()
      .url(TOKEN())
      .header("Authorization", Credentials.basic(CLIENT_ID, CLIENT_SECRET))
      .post(form)
      .build();

    try (Response r = HTTP.newCall(req).execute()) {
      if (!r.isSuccessful()) throw new IOException(r.body().string());
      storeTokens(r.body().string());
    }
  }

  static synchronized String ensureAccess() throws IOException {
    if (tok.access == null || Instant.now().isAfter(tok.exp.minusSeconds(60))) {
      refresh();
    }
    return tok.access;
  }

  static void refresh() throws IOException {
    if (tok.refresh == null) return; 
    RequestBody form = new FormBody.Builder()
      .add("grant_type", "refresh_token")
      .add("refresh_token", tok.refresh)
      .build();

    Request req = new Request.Builder()
      .url(TOKEN())
      .header("Authorization", Credentials.basic(CLIENT_ID, CLIENT_SECRET))
      .post(form)
      .build();

    try (Response r = HTTP.newCall(req).execute()) {
      if (!r.isSuccessful()) throw new IOException(r.body().string());
      storeTokens(r.body().string());
    }
  }

  static void storeTokens(String json) {
    JsonObject o = JsonParser.parseString(json).getAsJsonObject();
    tok.access  = o.get("access_token").getAsString();
    tok.exp     = Instant.now().plusSeconds(o.get("expires_in").getAsLong());
    if (o.has("refresh_token")) tok.refresh = o.get("refresh_token").getAsString();
    System.out.println("Access token acquired. Expires at: " + tok.exp);
  }


  static Map<String,String> parse(String q) {
    Map<String,String> m = new HashMap<>();
    if (q == null) return m;
    for (String p : q.split("&")) {
      String[] kv = p.split("=", 2);
      if (kv.length == 2) {
        m.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
              URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
      }
    }
    return m;
  }

  static String enc(String s) {
    try {
      return URLEncoder.encode(s, "UTF-8").replace("+", "%20");
    } catch (Exception e) {
      return s;
    }
  }

  static void open(String u) {
    try {
      if (Desktop.isDesktopSupported()) Desktop.getDesktop().browse(URI.create(u));
      else System.out.println("Open this URL manually:\n" + u);
    } catch (Exception e) {
      System.out.println("Open this URL manually:\n" + u);
    }
  }
}
