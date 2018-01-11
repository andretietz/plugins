// Copyright 2017, the Flutter project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

package io.flutter.plugins.googlesignin;

import android.app.Activity;
import android.app.Application;
import android.app.Application.ActivityLifecycleCallbacks;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.text.TextUtils;
import android.util.Log;

import com.google.android.gms.auth.api.signin.GoogleSignIn;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.auth.api.signin.GoogleSignInClient;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.auth.api.signin.GoogleSignInStatusCodes;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.CommonStatusCodes;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry;

/**
 * Google sign-in plugin for Flutter.
 */
public final class GoogleSignInPlugin implements MethodCallHandler {
  private static final String CHANNEL_NAME = "plugins.flutter.io/google_sign_in";

  private static final String TAG = "flutter";

  private static final String METHOD_INIT = "init";
  private static final String METHOD_SIGN_IN_SILENTLY = "signInSilently";
  private static final String METHOD_SIGN_IN = "signIn";
  private static final String METHOD_GET_TOKENS = "getTokens";
  private static final String METHOD_SIGN_OUT = "signOut";
  private static final String METHOD_DISCONNECT = "disconnect";

  private final Delegate delegate;

  private GoogleSignInPlugin(PluginRegistry.Registrar registrar) {
    delegate = new Delegate(registrar);
  }

  public static void registerWith(PluginRegistry.Registrar registrar) {
    final MethodChannel channel = new MethodChannel(registrar.messenger(), CHANNEL_NAME);
    final GoogleSignInPlugin instance = new GoogleSignInPlugin(registrar);
    channel.setMethodCallHandler(instance);
  }

  @Override
  public void onMethodCall(MethodCall call, Result result) {
    switch (call.method) {
      case METHOD_INIT:
        List<String> requestedScopes = call.argument("scopes");
        String hostedDomain = call.argument("hostedDomain");
        delegate.init(result, requestedScopes, hostedDomain);
        break;

      case METHOD_SIGN_IN_SILENTLY:
        delegate.signInSilently(result);
        break;

      case METHOD_SIGN_IN:
        delegate.signIn(result);
        break;

      case METHOD_GET_TOKENS:
        String email = call.argument("email");
        delegate.getTokens(result, email);
        break;

      case METHOD_SIGN_OUT:
        delegate.signOut(result);
        break;

      case METHOD_DISCONNECT:
        delegate.disconnect(result);
        break;

      default:
        result.notImplemented();
    }
  }

  /**
   * Delegate class that does the work for the Google sign-in plugin. This is exposed as a dedicated
   * class for use in other plugins that wrap basic sign-in functionality.
   * <p>
   * <p>All methods in this class assume that they are run to completion before any other method is
   * invoked. In this context, "run to completion" means that their {@link Result} argument has been
   * completed (either successfully or in error). This class provides no synchronization consructs
   * to guarantee such behavior; callers are responsible for providing such guarantees.
   */
  public static final class Delegate {
    private static final int REQUEST_CODE = 53293;
    private static final int REQUEST_CODE_RESOLVE_ERROR = 1001;

    private static final String ERROR_REASON_EXCEPTION = "exception";
    private static final String ERROR_REASON_STATUS = "status";

    private static final String STATE_RESOLVING_ERROR = "resolving_error";

    private final PluginRegistry.Registrar registrar;
    private final Handler handler = new Handler();

    private boolean resolvingError = false; // Whether we are currently resolving a sign-in error
    private GoogleSignInClient googleSignInClient;
    private List<String> requestedScopes;
    private PendingOperation pendingOperation;

    public Delegate(PluginRegistry.Registrar registrar) {
      this.registrar = registrar;
      Application application = (Application) registrar.context();
      application.registerActivityLifecycleCallbacks(handler);
      registrar.addActivityResultListener(handler);
    }

    /**
     * Returns the most recently signed-in account, or null if there was none.
     */
    public GoogleSignInAccount getCurrentAccount() {
      return GoogleSignIn.getLastSignedInAccount(registrar.context());
    }

    private void checkAndSetPendingOperation(String method, Result result) {
      if (pendingOperation != null) {
        throw new IllegalStateException(
            "Concurrent operations detected: " + pendingOperation.method + ", " + method);
      }
      pendingOperation = new PendingOperation(method, result);
    }

    /**
     * Initializes this delegate so that it is ready to perform other operations. The Dart code
     * guarantees that this will be called and completed before any other methods are invoked.
     */
    public void init(Result result, List<String> requestedScopes, String hostedDomain) {
      // We're not initialized until we receive `onConnected`.
      // If initialization fails, we'll receive `onConnectionFailed`
      checkAndSetPendingOperation(METHOD_INIT, result);

      try {
        GoogleSignInOptions.Builder optionsBuilder =
            new GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN).requestEmail();
        // Only requests a clientId if google-services.json was present and parsed
        // by the google-services Gradle script.
        // TODO(jackson): Perhaps we should provide a mechanism to override this
        // behavior.
        int clientIdIdentifier =
            registrar
                .context()
                .getResources()
                .getIdentifier(
                    "default_web_client_id", "string", registrar.context().getPackageName());
        if (clientIdIdentifier != 0) {
          optionsBuilder.requestIdToken(registrar.context().getString(clientIdIdentifier));
        }
        for (String scope : requestedScopes) {
          optionsBuilder.requestScopes(new Scope(scope));
        }
        if (!TextUtils.isEmpty(hostedDomain)) {
          optionsBuilder.setHostedDomain(hostedDomain);
        }

        this.requestedScopes = requestedScopes;

        googleSignInClient = GoogleSignIn.getClient(registrar.context(), optionsBuilder.build());
        GoogleApiAvailability apiAvailability = GoogleApiAvailability.getInstance();
        int availabilityResult = apiAvailability.isGooglePlayServicesAvailable(registrar.context());
        if (availabilityResult != ConnectionResult.SUCCESS) {
          if (registrar.activity() == null) {
            throw new IllegalStateException("creating the error dialog requires an activity");
          }
          apiAvailability.getErrorDialog(registrar.activity(), availabilityResult,
              REQUEST_CODE_RESOLVE_ERROR).show();
        }
      } catch (Exception e) {
        Log.e(TAG, "Initialization error", e);
        result.error(ERROR_REASON_EXCEPTION, e.getMessage(), null);
      }
    }

    /**
     * Returns the account information for the user who is signed in to this app. If no user is
     * signed in, tries to sign the user in without displaying any user interface.
     */
    public void signInSilently(Result result) {
      checkAndSetPendingOperation(METHOD_SIGN_IN_SILENTLY, result);

      Task<GoogleSignInAccount> task = googleSignInClient.silentSignIn();
      if (task.isComplete()) {
        onSignInResult(task);
      } else {
        task.addOnCompleteListener(new OnCompleteListener<GoogleSignInAccount>() {
          @Override
          public void onComplete(@NonNull Task<GoogleSignInAccount> task) {
            onSignInResult(task);
          }
        });
      }
    }

    /**
     * Signs the user in via the sign-in user interface, including the OAuth consent flow if scopes
     * were requested.
     */
    public void signIn(Result result) {
      if (registrar.activity() == null) {
        throw new IllegalStateException("signIn needs a foreground activity");
      }
      checkAndSetPendingOperation(METHOD_SIGN_IN, result);

      Intent signInIntent = googleSignInClient.getSignInIntent();
      registrar.activity().startActivityForResult(signInIntent, REQUEST_CODE);
    }

    /**
     * Gets an OAuth access token with the scopes that were specified during initialization for the
     * user with the specified email address.
     */
    public void getTokens(final Result result, final String email) {
      checkAndSetPendingOperation(METHOD_GET_TOKENS, result);
      // gated from Dart code. Change result.success/error calls below to use finishWith()
      if (email == null) {
        result.error(ERROR_REASON_EXCEPTION, "Email is null", null);
        return;
      }
      GoogleSignInAccount account = getCurrentAccount();
      if (account != null) {
        result.success(account.getIdToken());
      } else {
        result.error(ERROR_REASON_EXCEPTION, "User not signed in.", null);
      }
    }

    /**
     * Signs the user out. Their credentials may remain valid, meaning they'll be able to silently
     * sign back in.
     */
    public void signOut(Result result) {
      checkAndSetPendingOperation(METHOD_SIGN_OUT, result);
      googleSignInClient.signOut();
      // could be improved by using the googleSignInClient.signOut() result
      finishWithSuccess(null);
    }

    /**
     * Signs the user out, and revokes their credentials.
     */
    public void disconnect(Result result) {
      checkAndSetPendingOperation(METHOD_DISCONNECT, result);
      googleSignInClient.revokeAccess();
      // could be improved by using the googleSignInClient.revokeAccess() result
      finishWithSuccess(null);
    }

    private void onSignInResult(Task<GoogleSignInAccount> result) {
      if (result.isSuccessful()) {
        try {
          GoogleSignInAccount account = result.getResult(ApiException.class);
          Map<String, Object> response = new HashMap<>();
          response.put("email", account.getEmail());
          response.put("id", account.getId());
          response.put("idToken", account.getIdToken());
          response.put("displayName", account.getDisplayName());
          if (account.getPhotoUrl() != null) {
            response.put("photoUrl", account.getPhotoUrl().toString());
          }
          finishWithSuccess(response);
        } catch (ApiException error) {
          if (error.getStatusCode() == GoogleSignInStatusCodes.SIGN_IN_CANCELLED ||
              error.getStatusCode() == CommonStatusCodes.SIGN_IN_REQUIRED) {
            // authentication canceled
            finishWithSuccess(null);
          }
        }
      } else {
        finishWithError(ERROR_REASON_STATUS, result.getException().toString());
      }
    }

    private void finishWithSuccess(Object data) {
      pendingOperation.result.success(data);
      pendingOperation = null;
    }

    private void finishWithError(String errorCode, String errorMessage) {
      pendingOperation.result.error(errorCode, errorMessage, null);
      pendingOperation = null;
    }

    private static class PendingOperation {
      final String method;
      final Result result;

      PendingOperation(String method, Result result) {
        this.method = method;
        this.result = result;
      }
    }

    private class Handler implements ActivityLifecycleCallbacks,
        PluginRegistry.ActivityResultListener {

      @Override
      public boolean onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != REQUEST_CODE) return false;
        if (pendingOperation == null || !pendingOperation.method.equals(METHOD_SIGN_IN)) {
          Log.w(TAG, "Unexpected activity result; sign-in not in progress");
          return false;
        }

        if (data == null) {
          finishWithError(ERROR_REASON_STATUS, "No intent data: " + resultCode);
          return true;
        }

        onSignInResult(GoogleSignIn.getSignedInAccountFromIntent(data));
        return true;
      }

      @Override
      public void onActivityCreated(Activity activity, Bundle bundle) {
        resolvingError = bundle != null && bundle.getBoolean(STATE_RESOLVING_ERROR, false);
      }

      @Override
      public void onActivityDestroyed(Activity activity) {
      }

      @Override
      public void onActivityPaused(Activity activity) {
      }

      @Override
      public void onActivityResumed(Activity activity) {
      }

      @Override
      public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        outState.putBoolean(STATE_RESOLVING_ERROR, resolvingError);
      }

      @Override
      public void onActivityStarted(Activity activity) {
      }

      @Override
      public void onActivityStopped(Activity activity) {
      }
    }
  }
}
