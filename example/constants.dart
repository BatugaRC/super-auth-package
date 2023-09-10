import 'package:flutter/material.dart';
import 'package:super_auth_package/auth_service.dart';

import 'api.dart';

const Color appBarColor = Color(0xFFFF6969);
const Color buttonColor = Color(0xFFBB2525);
const Color textColor = Colors.white;
const Color scaffoldColor = Color(0xFFFFF5E0);

final AuthService auth = AuthService(
  twitterApi,
  twitterApiSecret,
  googleClientId,
  googleRedirectUri,
  githubClientId,
  githubClientSecret,
  githubURL,
);
