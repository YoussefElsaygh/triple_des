import 'dart:async';

import 'package:flutter/services.dart';

class TripleDes {
  static const MethodChannel _channel = const MethodChannel('triple_des');

  static Future<String> decrypt3Des({String message, String key}) async {
    final String version =
        await _channel.invokeMethod('decrypt3Des', <String, dynamic>{"key": key, "message": message});
    return version;
  }

  static Future<String> encrypt3Des({String message, String key}) async {
    final String version =
        await _channel.invokeMethod('encrypt3Des', <String, dynamic>{"key": key, "message": message});
    return version;
  }
}
