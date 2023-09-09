library super_auth_package;

import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:local_auth/local_auth.dart';
import 'package:http/http.dart' as http;

class AuthService {
  final String twitterApiKey;
  final String twitterApiSecret;
  final String gooogleClientId;
  final String googleRedirectUri;
  final String githubClientId;
  final String githubClientSecret;
  final String githubRedirectUri;
  FirebaseAuth auth = FirebaseAuth.instance;
  final LocalAuthentication localAuth = LocalAuthentication();

  AuthService(
    this.twitterApiKey,
    this.twitterApiSecret,
    this.gooogleClientId,
    this.googleRedirectUri,
    this.githubClientId,
    this.githubClientSecret,
    this.githubRedirectUri,
  );

  Future<String> signInAnon() async {
    try {
      await auth.signInAnonymously();
      return "0";
    } catch (e) {
      return e.toString();
    }
  }

  Future<String> signOut() async {
    try {
      await auth.signOut();
      return "0";
    } catch (e) {
      return e.toString();
    }
  }

  Future<String> signInWithEmailAndPassword(
      String email, String password) async {
    try {
      await auth.signInWithEmailAndPassword(
        email: email,
        password: password,
      );
      return "0";
    } catch (e) {
      return e.toString();
    }
  }

  Future<String> signUp(String email, String password) async {
    try {
      await auth.createUserWithEmailAndPassword(
        email: email,
        password: password,
      );
      return "0";
    } catch (e) {
      return e.toString();
    }
  }

  Future<void> sendResetPasswordEmail(String email) async {
    await auth.sendPasswordResetEmail(email: email);
  }

  Future<String> signInWithFaceId() async {
    final bool canAuthenticateWithBiometrics =
        await localAuth.canCheckBiometrics;
    final bool canAuthenticate =
        canAuthenticateWithBiometrics || await localAuth.isDeviceSupported();
    if (canAuthenticate) {
      final List<BiometricType> availableBiometrics =
          await localAuth.getAvailableBiometrics();

      if (availableBiometrics.contains(BiometricType.face)) {
        try {
          await localAuth.authenticate(
            localizedReason: "Please authenticate",
            options: const AuthenticationOptions(biometricOnly: true),
          );
          return "0";
        } catch (e) {
          return e.toString();
        }
      } else {
        return "Your device does not support face id.";
      }
    } else {
      return "Your device does not support local authentication";
    }
  }

  Future<String> signInWithGoogle() async {
    try {
      final String clientId = gooogleClientId;
      final String redirectUri = googleRedirectUri;
      const String scopes = 'openid email profile';
      final authEndpoint =
          Uri.parse('https://accounts.google.com/o/oauth2/auth');
      final authParams = {
        'response_type': 'code',
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'scope': scopes,
      };
      final authUrl =
          Uri.https(authEndpoint.host, authEndpoint.path, authParams);
      launchUrl(authUrl);

      final authorizationResponse = await http.get(authUrl);
      final uri = Uri.parse(authorizationResponse.request!.url.toString());
      final authorizationCode = uri.queryParameters["code"];

      if (authorizationCode != null) {
        final tokenEndpoint =
            Uri.parse('https://accounts.google.com/o/oauth2/token');
        final tokenParams = {
          'code': authorizationCode,
          'client_id': clientId,
          'redirect_uri': redirectUri,
          'grant_type': 'authorization_code',
        };

        final tokenResponse = await http.post(tokenEndpoint, body: tokenParams);

        if (tokenResponse.statusCode == 200) {
          final tokenData = json.decode(tokenResponse.body);
          final accessToken = tokenData['access_token'];
          final idToken = tokenData['id_token'];
          AuthCredential credential = GoogleAuthProvider.credential(
              accessToken: accessToken, idToken: idToken);
          await auth.signInWithCredential(credential);
          return "0";
        } else {
          return "status 400";
        }
      } else {
        return "no auth code";
      }
    } catch (e) {
      return e.toString();
    }
  }

  Future<String?> signInWithTwitter(BuildContext context) async {
    try {
      final String apiKey = twitterApiKey;
      final String apiSecretKey = twitterApiSecret;
      const String requestTokenUrl =
          'https://api.twitter.com/oauth/request_token';
      const String authorizeUrl = 'https://api.twitter.com/oauth/authorize';
      const String accessTokenUrl =
          'https://api.twitter.com/oauth/access_token';
      String oauthToken = '';
      String oauthTokenSecret = '';

      final String oauthNonce =
          DateTime.now().millisecondsSinceEpoch.toString();
      final String oauthTimestamp =
          (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();

      final Map<String, String> oauthParams = {
        'oauth_consumer_key': apiKey,
        'oauth_nonce': oauthNonce,
        'oauth_signature_method': 'HMAC-SHA1',
        'oauth_timestamp': oauthTimestamp,
        'oauth_version': '1.0',
      };
      final Uri baseUri = Uri.parse(requestTokenUrl);
      final String baseString =
          'POST&${Uri.encodeComponent(baseUri.toString())}&${Uri.encodeComponent(oauthParams.entries.map((e) => '${e.key}=${e.value}').join('&'))}';

      final String signingKey = '${Uri.encodeComponent(apiSecretKey)}&';
      final String oauthSignature = base64.encode(
          Hmac(sha1, utf8.encode(signingKey))
              .convert(utf8.encode(baseString))
              .bytes);

      oauthParams['oauth_signature'] = Uri.encodeComponent(oauthSignature);
      final String authorizationHeader =
          'OAuth ${oauthParams.entries.map((e) => '${e.key}="${e.value}"').join(', ')}';

      final http.Response response = await http.post(
        Uri.parse(requestTokenUrl),
        headers: {'Authorization': authorizationHeader},
      );

      if (response.statusCode == 200) {
        final Map<String, String> requestTokenParams =
            Uri.splitQueryString(response.body);
        oauthToken = requestTokenParams['oauth_token']!;
        oauthTokenSecret = requestTokenParams['oauth_token_secret']!;

        final String authorizeRedirectUrl =
            '$authorizeUrl?oauth_token=$oauthToken';

        launchUrl(Uri.parse(authorizeRedirectUrl));
        Uri callbackUri = Uri.parse(
            "https://super-auth-g103.firebaseapp.com/__/auth/handler");
        final Map<String, String> queryParams = callbackUri.queryParameters;
        final String oauthVerifier = queryParams['oauth_verifier']!;

        final String oauthNonce =
            DateTime.now().millisecondsSinceEpoch.toString();
        final String oauthTimestamp =
            (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();

        final Map<String, String> oauthParams = {
          'oauth_consumer_key': apiKey,
          'oauth_nonce': oauthNonce,
          'oauth_signature_method': 'HMAC-SHA1',
          'oauth_timestamp': oauthTimestamp,
          'oauth_token': oauthToken,
          'oauth_verifier': oauthVerifier,
          'oauth_version': '1.0',
        };

        final Uri baseUri = Uri.parse(accessTokenUrl);
        final String baseString =
            'POST&${Uri.encodeComponent(baseUri.toString())}&${Uri.encodeComponent(oauthParams.entries.map((e) => '${e.key}=${e.value}').join('&'))}';

        final String signingKey =
            '${Uri.encodeComponent(apiSecretKey)}&${Uri.encodeComponent(oauthTokenSecret)}';
        final String oauthSignature = base64.encode(
            Hmac(sha1, utf8.encode(signingKey))
                .convert(utf8.encode(baseString))
                .bytes);
        oauthParams['oauth_signature'] = Uri.encodeComponent(oauthSignature);
        final String authorizationHeader =
            'OAuth ${oauthParams.entries.map((e) => '${e.key}="${e.value}"').join(', ')}';
        final http.Response response1 = await http.post(
          Uri.parse(accessTokenUrl),
          headers: {'Authorization': authorizationHeader},
        );

        if (response1.statusCode == 200) {
          final Map<String, String> accessTokenParams =
              Uri.splitQueryString(response1.body);
          String? accessToken = accessTokenParams["access_token"];
          print(accessToken);
          return "0";
          // Optionally, you can store the access token securely for future use.
        } else {
          return "error";
        }
      } else {
        return "error";
      }
    } on FirebaseAuthException catch (e) {
      return e.code;
    } catch (e) {
      return e.toString();
    }
  }

  Future<String> signInWithGithub(final context) async {
    try {
      const String clientId = '937225abd492ba640715';
      const String clientSecret = '3481d1c649d8ea0726189a7c6f1cfc6a19894204';
      const String redirectUri = 'super-auth://';
      final authEndpoint =
          Uri.parse('https://github.com/login/oauth/authorize');
      final tokenEndpoint =
          Uri.parse('https://github.com/login/oauth/access_token');

      final state = DateTime.now().millisecondsSinceEpoch.toString();

      final authParams = {
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'state': state,
        'scope': 'user',
      };
      final authUrl =
          Uri.https(authEndpoint.host, authEndpoint.path, authParams);

      launchUrl(authUrl);

      final authorizationResponse = await http.get(authUrl);
      final uri = Uri.parse(authorizationResponse.request!.url.toString());
      final authorizationCode = uri.queryParameters['code'];

      if (authorizationCode != null) {
        final tokenParams = {
          'client_id': clientId,
          'client_secret': clientSecret,
          'code': authorizationCode,
          'redirect_uri': redirectUri,
          'state': state,
        };
        final tokenResponse = await http.post(tokenEndpoint, body: tokenParams);

        if (tokenResponse.statusCode == 200) {
          final tokenData = json.decode(tokenResponse.body);
          final accessToken = tokenData['access_token'];
          final AuthCredential credential =
              GithubAuthProvider.credential(accessToken);
          await auth.signInWithCredential(credential);
          return '0';
        } else {
          return 'GitHub token exchange failed';
        }
      } else {
        return 'No GitHub authorization code';
      }
    } catch (e) {
      return e.toString();
    }
  }
}
