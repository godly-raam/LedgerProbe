/* FinShield-Core Frida harness.
 *
 * Attach to the mock banking app and emit telemetry about SIM-binding and
 * attestation calls. Every payload is a plain JSON object consumed by runner.py.
 */
"use strict";

function emit(type, signal, value) {
  send({ type: type, signal: signal, value: value === undefined ? null : String(value) });
}

function hookMethod(className, methodName, type, signal) {
  try {
    var klass = Java.use(className);
    var overloads = klass[methodName].overloads;
    overloads.forEach(function (overload) {
      overload.implementation = function () {
        var value = overload.call(this);
        emit(type, signal, value);
        return value;
      };
    });
    emit("hook", "installed", className + "#" + methodName);
  } catch (error) {
    emit("hook_error", className + "#" + methodName, error);
  }
}

Java.perform(function () {
  emit("harness", "ready", "frida " + Frida.version);

  hookMethod("android.telephony.TelephonyManager", "getSimSerialNumber", "telephony", "sim_serial_read");
  hookMethod("android.telephony.TelephonyManager", "getSubscriberId", "telephony", "subscriber_id_read");
  hookMethod("android.telephony.TelephonyManager", "getDeviceId", "telephony", "device_id_read");

  // StrongBox / TEE selection happens on the key generator spec builder.
  try {
    var Builder = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
    Builder.setIsStrongBoxBacked.implementation = function (enabled) {
      emit("keystore", "strongbox_requested", enabled);
      return this.setIsStrongBoxBacked(enabled);
    };
    Builder.setUserAuthenticationRequired.implementation = function (required) {
      emit("keystore", "user_auth_required", required);
      return this.setUserAuthenticationRequired(required);
    };
    emit("hook", "installed", "KeyGenParameterSpec$Builder");
  } catch (error) {
    emit("hook_error", "KeyGenParameterSpec$Builder", error);
  }

  try {
    var KeyStore = Java.use("java.security.KeyStore");
    KeyStore.getInstance.overload("java.lang.String").implementation = function (provider) {
      emit("keystore", "provider_requested", provider);
      return this.getInstance(provider);
    };
    emit("hook", "installed", "KeyStore#getInstance");
  } catch (error) {
    emit("hook_error", "KeyStore#getInstance", error);
  }

  try {
    var Build = Java.use("android.os.Build");
    emit("device", "build_tags", Build.TAGS.value);
    emit("device", "manufacturer", Build.MANUFACTURER.value);
    emit("device", "model", Build.MODEL.value);
    emit("device", "fingerprint", Build.FINGERPRINT.value);
  } catch (error) {
    emit("hook_error", "android.os.Build", error);
  }

  try {
    var Runtime = Java.use("java.lang.Runtime");
    var exec = Runtime.exec.overload("java.lang.String");
    exec.implementation = function (command) {
      emit("root", "shell_exec", command);
      return exec.call(this, command);
    };
  } catch (error) {
    emit("hook_error", "Runtime#exec", error);
  }

  try {
    var SmsManager = Java.use("android.telephony.SmsManager");
    SmsManager.sendTextMessage.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit("sms", "outbound_sms", overload.argumentTypes.length);
        return overload.apply(this, arguments);
      };
    });
    emit("hook", "installed", "SmsManager#sendTextMessage");
  } catch (error) {
    emit("hook_error", "SmsManager#sendTextMessage", error);
  }

  try {
    var KeyInfo = Java.use("android.security.keystore.KeyInfo");
    emit("keystore", "key_info_available", KeyInfo.class.getName());
  } catch (error) {
    emit("hook_error", "KeyInfo", error);
  }

  emit("harness", "hooks_loaded", "all");
});
