// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:mockito/mockito.dart';
import 'package:platform/platform.dart';
import 'package:test/test.dart';

void main() {
  MockMethodChannel mockChannel;
  FirebaseMessaging firebaseMessaging;

  setUp(() {
    mockChannel = new MockMethodChannel();
    firebaseMessaging = new FirebaseMessaging.private(
        mockChannel, new FakePlatform(operatingSystem: 'ios'));
  });

  test('requestNotificationPermissions on ios with default permissions', () {
    firebaseMessaging.requestNotificationPermissions();
    verify(mockChannel.invokeMethod('requestNotificationPermissions',
        <String, bool>{'sound': true, 'badge': true, 'alert': true}));
  });

  test('requestNotificationPermissions on ios with custom permissions', () {
    firebaseMessaging.requestNotificationPermissions(
        const IosNotificationSettings(sound: false));
    verify(mockChannel.invokeMethod('requestNotificationPermissions',
        <String, bool>{'sound': false, 'badge': true, 'alert': true}));
  });

  test('requestNotificationPermissions on android', () {
    firebaseMessaging = new FirebaseMessaging.private(
        mockChannel, new FakePlatform(operatingSystem: 'android'));

    firebaseMessaging.requestNotificationPermissions();
    verifyZeroInteractions(mockChannel);
  });

  test('requestNotificationPermissions on android', () {
    firebaseMessaging = new FirebaseMessaging.private(
        mockChannel, new FakePlatform(operatingSystem: 'android'));

    firebaseMessaging.requestNotificationPermissions();
    verifyZeroInteractions(mockChannel);
  });

  test('configure', () {
    firebaseMessaging.configure();
    verify(mockChannel.setMethodCallHandler(any));
    verify(mockChannel.invokeMethod('configure'));
  });

  test('incoming token', () async {
    firebaseMessaging.configure();
    final dynamic handler =
        verify(mockChannel.setMethodCallHandler(captureAny)).captured.single;
    final String token1 = 'I am a super secret token';
    final String token2 = 'I am the new token in town';
    Future<String> tokenFromStream = firebaseMessaging.onTokenRefresh.first;
    await handler(new MethodCall('onToken', token1));

    expect(await firebaseMessaging.getToken(), token1);
    expect(await tokenFromStream, token1);

    tokenFromStream = firebaseMessaging.onTokenRefresh.first;
    await handler(new MethodCall('onToken', token2));

    expect(await firebaseMessaging.getToken(), token2);
    expect(await tokenFromStream, token2);
  });

  test('incoming iOS settings', () async {
    firebaseMessaging.configure();
    final dynamic handler =
        verify(mockChannel.setMethodCallHandler(captureAny)).captured.single;
    IosNotificationSettings iosSettings = const IosNotificationSettings();

    Future<IosNotificationSettings> iosSettingsFromStream =
        firebaseMessaging.onIosSettingsRegistered.first;
    await handler(
        new MethodCall('onIosSettingsRegistered', iosSettings.toMap()));
    expect((await iosSettingsFromStream).toMap(), iosSettings.toMap());

    iosSettings = const IosNotificationSettings(sound: false);
    iosSettingsFromStream = firebaseMessaging.onIosSettingsRegistered.first;
    await handler(
        new MethodCall('onIosSettingsRegistered', iosSettings.toMap()));
    expect((await iosSettingsFromStream).toMap(), iosSettings.toMap());
  });

  test('incoming messages', () async {
    final Completer<dynamic> onMessage = new Completer<dynamic>();
    final Completer<dynamic> onLaunch = new Completer<dynamic>();
    final Completer<dynamic> onResume = new Completer<dynamic>();

    firebaseMessaging.configure(onMessage: (dynamic m) {
      onMessage.complete(m);
    }, onLaunch: (dynamic m) {
      onLaunch.complete(m);
    }, onResume: (dynamic m) {
      onResume.complete(m);
    });
    final dynamic handler =
        verify(mockChannel.setMethodCallHandler(captureAny)).captured.single;

    final Object onMessageMessage = new Object();
    final Object onLaunchMessage = new Object();
    final Object onResumeMessage = new Object();

    await handler(new MethodCall('onMessage', onMessageMessage));
    expect(await onMessage.future, onMessageMessage);
    expect(onLaunch.isCompleted, isFalse);
    expect(onResume.isCompleted, isFalse);

    await handler(new MethodCall('onLaunch', onLaunchMessage));
    expect(await onLaunch.future, onLaunchMessage);
    expect(onResume.isCompleted, isFalse);

    await handler(new MethodCall('onResume', onResumeMessage));
    expect(await onResume.future, onResumeMessage);
  });

  const String myTopic = 'Flutter';

  test('subscribe to topic', () {
    firebaseMessaging.subscribeToTopic(myTopic);
    verify(mockChannel.invokeMethod('subscribeToTopic', myTopic));
  });

  test('unsubscribe from topic', () {
    firebaseMessaging.unsubscribeFromTopic(myTopic);
    verify(mockChannel.invokeMethod('unsubscribeFromTopic', myTopic));
  });
}

class MockMethodChannel extends Mock implements MethodChannel {}
